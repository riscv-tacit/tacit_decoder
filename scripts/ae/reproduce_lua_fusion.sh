#!/usr/bin/env bash
#
# Artifact Evaluation driver: profile-guided dispatch fusion in a Lua interpreter.
#
# Reproduces the mandelbrot case study end to end for three interpreter arms:
#
#   base     unfused                                   (reference)
#   mulmul   one guard,  MUL -> MUL                    (1 hand-edited token)
#   mmadd    two guards, MUL -> MUL and MUL -> ADD
#
# and for each arm does: build -> host check -> image -> FPGA run -> bundle ->
# decode -> analyse, then prints one comparison table.
#
# Usage
#   ./reproduce_lua_fusion.sh                          everything, all three arms
#   ./reproduce_lua_fusion.sh --arms base,mulmul       a subset, in this order
#   ./reproduce_lua_fusion.sh --stages decode,analyse  no FPGA needed if bundles exist
#   ./reproduce_lua_fusion.sh --force                  redo stages whose output exists
#   ./reproduce_lua_fusion.sh --list                   show the plan and exit
#
# Stages are resumable: a stage whose output is already present is skipped unless
# --force. That matters because the FPGA stages are the long ones and a reviewer
# who hits a failure in `analyse` should not have to re-run the simulator.
#
# Requirements
#   FPGA stages : a Xilinx Alveo U250 with the tacit_mega_boom_v3_sramqueue_lossy
#                 bitstream already built (see results-build/), and exclusive use
#                 of the run farm -- the runs are serialised here for that reason.
#   decode      : ~32 GB free RAM per decode (bb_pair_stats dominates; use
#                 --narrow to drop it and roughly halve both time and memory).
#   no FPGA     : --stages decode,analyse,report works from the shipped bundles in
#                 tacit_decoder/bundles/ (each is self-contained: trace, binaries,
#                 kernel/driver dwarf, and a config with bundle-relative paths).
#
# Rough wall-clock, per arm: build 2 min, image 4 min, run 8 min, bundle 2 min,
# decode 15 min, analyse 1 min. All three arms end to end is about 1h45.
set -uo pipefail

CY=/scratch/iansseijelly/tacit-chipyard
TD=$CY/software/tacit_decoder
LD=$CY/software/lua-dispatch
FM=$CY/software/firemarshal
FS=$CY/sims/firesim
PY=$CY/.conda-env/bin/python3
OBJDUMP=$CY/.conda-env/riscv-tools/bin/riscv64-unknown-elf-objdump

ARMS=base,mulmul,mmadd
STAGES=build,image,run,bundle,decode,analyse,report
FORCE=0; NARROW=0; LIST=0
OUT=$TD/ae-out

while [ $# -gt 0 ]; do
  case "$1" in
    --arms)   ARMS=$2; shift 2 ;;
    --stages) STAGES=$2; shift 2 ;;
    --out)    OUT=$2; shift 2 ;;
    --force)  FORCE=1; shift ;;
    --narrow) NARROW=1; shift ;;
    --list)   LIST=1; shift ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------- per-arm table
# tree | workload | runtime config | optab | firesim job dir | bundle
arm_spec() {
  case "$1" in
    base)   echo "lua-fuse-base|lua-fuse-base-mb|config_runtime_lua_base.yaml|lua_optab_fusebase.json|lua-fuse-base-mb-base-mandelbrot-traced|lua-fuse-base-mandelbrot-20260901" ;;
    mulmul) echo "lua-fuse-mulmul|lua-fuse-mulmul|config_runtime_lua_mulmul.yaml|lua_optab_mulmul.json|lua-fuse-mulmul-mulmul-mandelbrot-traced|lua-fuse-mulmul-mandelbrot-20260903" ;;
    mmadd)  echo "lua-fuse-mulmul-muladd|lua-fuse-mmadd|config_runtime_lua_mmadd.yaml|lua_optab_mulmul_muladd.json|lua-fuse-mmadd-mmadd-mandelbrot-traced|lua-fuse-mmadd-mandelbrot-20260903" ;;
    # the span-vs-entry test: a guard the span profile ranks 4th and the entry-block profile
    # says is already predicted, with its own layout control in the same workload
    leimul)    echo "lua-fuse-leimul|lua-fuse-leimul|config_runtime_lua_leimul.yaml|lua_optab_leimul.json|lua-fuse-leimul-leimul-mandelbrot-traced|lua-fuse-leimul-mandelbrot-20260907" ;;
    leimulctl) echo "lua-leimul-gt127|lua-fuse-leimul|config_runtime_lua_leimul.yaml|lua_optab_leimul.json|lua-fuse-leimul-leimul-gt127-mandelbrot-traced|lua-leimul-gt127-mandelbrot-20260907" ;;
    *) return 1 ;;
  esac
}
ARM_LABEL() { case "$1" in base) echo 'baseline' ;; mulmul) echo '+MUL→MUL' ;; mmadd) echo '+MUL→ADD' ;; leimul) echo '+LEI→MUL' ;; leimulctl) echo 'LEI→MUL control' ;; esac; }
# FireSim names each job's results dir <workload>-<job>, so the chores dir carries the prefix
CHORES_JOB() { case "$1" in base) echo lua-fuse-base-mb-base-chores ;; mulmul) echo lua-fuse-mulmul-mulmul-chores ;; mmadd) echo lua-fuse-mmadd-mmadd-chores ;; leimul|leimulctl) echo lua-fuse-leimul-leimul-chores ;; esac; }
WL_PREFIX()  { case "$1" in base) echo lua-fuse-base-mb ;; mulmul) echo lua-fuse-mulmul ;; mmadd) echo lua-fuse-mmadd ;; leimul|leimulctl) echo lua-fuse-leimul ;; esac; }
# name of the interpreter binary inside the overlay (one workload can carry several)
APP_NAME()   { case "$1" in leimul) echo lua-leimul ;; leimulctl) echo lua-leimul-gt127 ;; *) echo lua ;; esac; }

has_stage() { [[ ",$STAGES," == *",$1,"* ]]; }
say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
step() { printf '   %-46s' "$*"; }
ok()   { printf 'ok%s\n' "${1:+  ($1)}"; }
skip() { printf 'skip  (%s)\n' "$1"; }
die()  { printf 'FAILED\n'; echo "   see $1" >&2; exit 1; }

# The env is the fiddliest part of this artifact, so it is done once, correctly:
#   - sourceme-manager.sh does a relative ./env.sh, so it MUST be sourced from
#     sims/firesim, not from deploy/
#   - never source through a pipe; the subshell discards the env
setup_env() {
  # Third-party activation scripts (conda's riscv-tools hook, sourceme-manager)
  # reference unset variables, so -u has to stand down while they run.
  set +u
  # shellcheck disable=SC1090,SC1091
  source $CY/.conda-env/etc/profile.d/conda.sh
  source $CY/env.sh
  # must be sourced FROM sims/firesim: the script does a relative ./env.sh
  cd $FS && source ./sourceme-manager.sh --skip-ssh-setup >/dev/null 2>&1
  [ -f /ecad/tools/xilinx/Vitis/2021.1/settings64.sh ] && \
    source /ecad/tools/xilinx/Vitis/2021.1/settings64.sh >/dev/null 2>&1
  set -u
  cd "$OUT"
}

CFLAGS="-O2 -g -static -fno-crossjumping"
mkdir -p "$OUT"/logs
IFS=, read -r -a ARM_LIST <<< "$ARMS"

if [ $LIST -eq 1 ]; then
  echo "arms   : ${ARM_LIST[*]}"
  echo "stages : $STAGES"
  echo "out    : $OUT"
  for arm in "${ARM_LIST[@]}"; do
    IFS='|' read -r tree wl cfg optab job bundle <<< "$(arm_spec "$arm")"
    printf '  %-8s tree=%-24s workload=%-18s cfg=%s\n' "$arm" "$tree" "$wl" "$cfg"
  done
  exit 0
fi

setup_env
say "environment"
step "riscv gcc";  command -v riscv64-unknown-linux-gnu-gcc >/dev/null && ok "$(riscv64-unknown-linux-gnu-gcc -dumpversion)" || die "PATH"
step "firesim";    if has_stage run; then command -v firesim >/dev/null && ok || die "sourceme-manager"; else skip "run stage not selected"; fi
step "python deps"; $PY -c 'import pandas, matplotlib, elftools' 2>/dev/null && ok || die "pip install pandas matplotlib pyelftools"

for arm in "${ARM_LIST[@]}"; do
  IFS='|' read -r tree wl cfg optab job bundle <<< "$(arm_spec "$arm")" || { echo "unknown arm: $arm" >&2; exit 2; }
  L=$OUT/logs/$arm
  say "arm: $arm   ($tree)"

  # ---------------------------------------------------------------- build
  if has_stage build; then
    step "build riscv interpreter"
    if [ -x $LD/$tree/src/lua ] && [ $FORCE -eq 0 ]; then
      skip "$(md5sum < $LD/$tree/src/lua | cut -c1-12)"
    else
      make -C $LD/$tree/src clean >/dev/null 2>&1
      make -C $LD/$tree/src posix -j"$(nproc)" \
        CC="riscv64-unknown-linux-gnu-gcc -std=gnu99" \
        AR="riscv64-unknown-linux-gnu-ar rcu" RANLIB="riscv64-unknown-linux-gnu-ranlib" \
        MYCFLAGS="$CFLAGS" MYLDFLAGS="-static" > "$L.build.log" 2>&1 \
        && ok "$(md5sum < $LD/$tree/src/lua | cut -c1-12)" || die "$L.build.log"
    fi
    # A guard that jumps into the wrong handler is silent on small inputs, so gate
    # on the real workload before spending an FPGA run on it.
    step "host correctness gate"
    ( set -e
      rm -rf "$OUT/hostchk-$arm" && cp -r $LD/$tree "$OUT/hostchk-$arm"
      make -C "$OUT/hostchk-$arm/src" clean
      make -C "$OUT/hostchk-$arm/src" posix -j"$(nproc)" CC="gcc -std=gnu99" \
           MYCFLAGS="-O2 -fno-crossjumping"
      cd $LD
      for spec in "mandelbrot.lua 900" "spectralnorm.lua 200" "fannkuch.lua 8" "sieve.lua 200000"; do
        set -- $spec
        a=$("$OUT/hostchk-$arm/src/lua" bench/$1 $2 </dev/null)
        b=$(lua-host/src/lua           bench/$1 $2 </dev/null)
        [ "$a" = "$b" ] || { echo "MISMATCH on $1 $2: '$a' != '$b'"; exit 1; }
      done ) > "$L.hostchk.log" 2>&1 && ok "4 benchmarks match" || die "$L.hostchk.log"
  fi

  # ---------------------------------------------------------------- image
  if has_stage image; then
    step "firemarshal image"
    IMG=$FM/images/firechip/$job/$job.img
    if [ -f "$IMG" ] && [ $FORCE -eq 0 ]; then skip "$(basename "$IMG")"; else
      install -m755 $LD/$tree/src/lua $FM/example-workloads/$wl/overlay/root/lua-dispatch/$(APP_NAME "$arm")
      rm -f $FM/example-workloads/$wl/overlay/root/lua-dispatch/trace-run
      ( cd $FM && ./marshal -v build example-workloads/$wl.json ) > "$L.image.log" 2>&1 \
        && ok || die "$L.image.log"
    fi
    # The guest must be running the interpreter we just built; a stale overlay
    # copy would produce a run that looks fine and measures nothing.
    step "verify rootfs interpreter"
    want=$(md5sum < $LD/$tree/src/lua | cut -c1-32)
    got=$(debugfs -R "dump /root/lua-dispatch/$(APP_NAME "$arm") $OUT/.img.lua" "$IMG" 2>/dev/null; md5sum < "$OUT/.img.lua" | cut -c1-32)
    [ "$want" = "$got" ] && ok "${want:0:12}" || { printf 'FAILED\n   rootfs has %s, expected %s\n' "${got:0:12}" "${want:0:12}"; exit 1; }
    ( cd $FM && ./marshal install example-workloads/$wl.json ) >> "$L.image.log" 2>&1
  fi

  # ---------------------------------------------------------------- FPGA run
  if has_stage run; then
    step "FPGA run (serialised)"
    R=$(ls -dt $FS/deploy/results-workload/*"$(WL_PREFIX "$arm")" 2>/dev/null | head -1)
    if [ -n "$R" ] && [ -f "$R/$job/uartlog" ] && [ $FORCE -eq 0 ]; then
      skip "$(basename "$R")"
    else
      ( cd $FS/deploy && firesim -c "$cfg" infrasetup && firesim -c "$cfg" runworkload ) \
        > "$L.run.log" 2>&1 || die "$L.run.log"
      R=$(ls -dt $FS/deploy/results-workload/*"$(WL_PREFIX "$arm")" | head -1)
      ok "$(basename "$R")"
    fi
    echo "$R" > "$OUT/.results.$arm"
  fi

  # ---------------------------------------------------------------- bundle
  if has_stage bundle; then
    step "bundle capture"
    B=$TD/bundles/$bundle
    if [ -f "$B/config.json" ] && [ $FORCE -eq 0 ]; then skip "$(du -sh "$B" | cut -f1)"; else
      R=$(cat "$OUT/.results.$arm" 2>/dev/null || ls -dt $FS/deploy/results-workload/*"$(WL_PREFIX "$arm")" | head -1)
      tpl=$([ $NARROW -eq 1 ] && echo lua-fuse-narrow.json || echo lua-fuse-vbb.json)
      $PY $TD/scripts/analysis/bundle_run.py \
        --results "$R/$job" --template $TD/configs/templates/$tpl --out "$B" \
        --image $FM/images/firechip/$job \
        --jlmap "$R/$(CHORES_JOB "$arm")/jump_label_patch_map.txt" \
        --app $FM/example-workloads/$wl/overlay/root/lua-dispatch/$(APP_NAME "$arm") \
        --app $FM/example-workloads/$wl/overlay/root/lua-dispatch/trace-run \
        > "$L.bundle.log" 2>&1 && ok "$(du -sh "$B" | cut -f1)" || die "$L.bundle.log"
    fi
  fi

  # ---------------------------------------------------------------- decode
  if has_stage decode; then
    step "decode from bundle"
    B=$TD/bundles/$bundle
    if [ -s "$B/out/lua.bb_stats.csv" ] && [ $FORCE -eq 0 ]; then skip "already decoded"; else
      mkdir -p "$B/out"
      ( cd "$B" && $TD/target/release/tacit-decoder --config config.json ) \
        > "$L.decode.log" 2>&1 && ok "$(wc -l < "$B/out/lua.bb_stats.csv") blocks" || die "$L.decode.log"
    fi
  fi

  # ---------------------------------------------------------------- analyse
  if has_stage analyse; then
    step "analysis flow"
    B=$TD/bundles/$bundle
    A=$OUT/$arm
    if [ -f "$A/vbb.mandelbrot.txt" ] && [ $FORCE -eq 0 ]; then skip "$A"; else
      mkdir -p "$A"
      for r in bb_stats bb_hist bb_pair_stats dispatch_stats dispatch_hist; do
        [ -f "$B/out/lua.$r.csv" ] && cp "$B/out/lua.$r.csv" "$A/trace.$arm.$r.csv"
      done
      win=$(grep -ao 'window_cycles~=[0-9]*' "$B/uartlog" | head -1 | cut -d= -f2)
      $PY - "$win" <<'EOP' > "$A/window.txt"
import sys; print(f'{int(sys.argv[1])/1e9:.6f}')
EOP
      ( cd $TD && ./scripts/analysis/run_mandelbrot_flow.sh \
          configs/lua/$optab "$A/trace.$arm" "$(cat "$A/window.txt")" "$A" ) \
        > "$L.analyse.log" 2>&1 && ok "$A" || die "$L.analyse.log"
    fi
  fi
done

# ---------------------------------------------------------------- report
if has_stage report; then
  say "results"
  # the boring bar chart, from the same uartlogs the table below parses
  step "runtime figure"
  BARS=(); GRID=(); missing=0
  for a in "${ARM_LIST[@]}"; do
    IFS='|' read -r _ _ _ optab _ bundle <<< "$(arm_spec "$a")"
    lbl=$(ARM_LABEL "$a")
    BARS+=("$lbl=$TD/bundles/$bundle")
    # the per-predecessor grid needs each arm's own optab: every handler moves
    # between builds, so an address means nothing without the arm that produced it
    h=$TD/bundles/$bundle/out/lua.dispatch_hist.csv
    [ -f "$h" ] && GRID+=("$lbl=$h:$TD/configs/lua/$optab") || missing=1
  done
  $PY $TD/scripts/analysis/plot_runtime_bars.py --out "$OUT/fig.runtime" "${BARS[@]}" \
    > "$OUT/logs/report.log" 2>&1 && ok "$OUT/fig.runtime.pdf" || skip "see logs/report.log"

  step "per-predecessor grid"
  if [ $missing -eq 1 ]; then
    skip "needs the decode stage for every arm"
  else
    $PY $TD/scripts/analysis/plot_pred_grid.py --targets MUL,ADD --row-height 44 \
      --out "$OUT/fig.pred_grid" "${GRID[@]}" \
      >> "$OUT/logs/report.log" 2>&1 && ok "$OUT/fig.pred_grid.pdf" \
      || skip "see logs/report.log"
  fi
  $PY - "$OUT" "$TD" "$LD" "${ARM_LIST[@]}" <<'EOP'
import json, re, sys, pathlib
out, td, ld, *arms = sys.argv[1:]
BUNDLE = {'base':'lua-fuse-base-mandelbrot-20260901','mulmul':'lua-fuse-mulmul-mandelbrot-20260903','mmadd':'lua-fuse-mmadd-mandelbrot-20260903',
          'leimul':'lua-fuse-leimul-mandelbrot-20260907','leimulctl':'lua-leimul-gt127-mandelbrot-20260907'}
TREE   = {'base':'lua-fuse-base','mulmul':'lua-fuse-mulmul','mmadd':'lua-fuse-mulmul-muladd','leimul':'lua-fuse-leimul','leimulctl':'lua-leimul-gt127'}
LABEL  = {'base':'unfused baseline','mulmul':'1 guard  MUL->MUL','mmadd':'2 guards MUL->MUL,MUL->ADD',
          'leimul':'1 guard  LEI->MUL (span pick)','leimulctl':'LEI->MUL layout control'}
rows=[]
for a in arms:
    u = pathlib.Path(td)/'bundles'/BUNDLE[a]/'uartlog'
    if not u.exists(): continue
    t = u.read_bytes().decode('utf8','replace')
    g = lambda p: (re.search(p,t) or [None,None])[1]
    r = dict(arm=a, win=int(g(r'window_cycles~=(\d+)') or 0),
             tot=int(g(r'PASSED \*\*\* after (\d+) cycles') or 0),
             chk=(g(r'(inset \d+ checksum \d+)') or '?'),
             stall=int(g(r'stall_cycles=(\d+)') or 0), entries=None, ft=None, declared=None)
    # the decoder's own account of what it saw: every handler entry, and every entry
    # point that reached a handler by falling through (a guard's edge stub)
    sm = pathlib.Path(td)/'bundles'/BUNDLE[a]/'out'/'lua.dispatch_stats.summary.json'
    if sm.exists():
        j = json.load(open(sm)); r['entries'] = j['entries_total']; r['ft'] = j['fallthrough_entries']
    # a guard is any handler entry NOT made by the indirect jr: a `beq` onto the edge stub in
    # front of the entry (fall-through, canonicalised) or a direct `j`/`beq` landing exactly on
    # the entry. Count distinct non-jr sites in the per-site table; that is what a declared
    # guard must produce, whichever way GCC laid it out.
    st = pathlib.Path(td)/'bundles'/BUNDLE[a]/'out'/'lua.dispatch_stats.sites.csv'
    if st.exists():
        import csv
        sites = set()
        for row in csv.DictReader(open(st), skipinitialspace=True):
            if row['site_kind'].strip() != 'jr' and int(row['count']) >= 10000:
                sites.add((row['site_pc'].strip(), row['site_kind'].strip(), row['to_handler'].strip()))
        r['gsites'] = sorted(sites)
    man = pathlib.Path(ld)/TREE[a]/'manifest.json'
    if man.exists():
        m = json.load(open(man))
        r['declared'] = 0 if m.get('placebo') else len(m.get('guards', []))
    rows.append(r)
if not rows:
    print('  no uartlogs found -- run the `run` and `bundle` stages first'); sys.exit(0)
base = rows[0]['win']
print(f"  {'arm':28} {'window cycles':>15} {'vs baseline':>12} {'total cycles':>15}  correctness")
for r in rows:
    d = f"{100*(r['win']-base)/base:+.2f}%" if base and r['win'] else '—'
    print(f"  {LABEL[r['arm']]:28} {r['win']:15,} {d:>12} {r['tot']:15,}  {r['chk']}")
same = len({r['chk'] for r in rows}) == 1
print(f"\n  program output identical across arms: {'YES' if same else 'NO -- INVESTIGATE'}")
print(f"  max trace-unit stall: {max(r['stall'] for r in rows)} cycles "
      f"(perturbation is nil if this is small vs the window)")

# --- instrument canaries -----------------------------------------------------------
# (1) the same workload executes the same bytecode in every arm, so the decoder must
#     see the same number of handler entries in every arm. A shortfall means arrivals
#     the instrument cannot see -- exactly the failure that once hid guarded arrivals.
# (2) the guards a tree declares are the only reason a handler is ever entered by
#     falling through a stub; the count of such entry points must match the declaration.
have = [r for r in rows if r['entries'] is not None]
if have:
    print(f"\n  {'arm':28} {'handler entries':>16} {'vs baseline':>12} {'non-jr entry sites':>19} {'declared guards':>16}  check")
    ref = have[0]['entries']; ok_all = True
    for r in have:
        dev = abs(r['entries'] - ref) / ref
        gs = r.get('gsites') or []; dec = r['declared']
        ok = dev < 1e-4 and (dec is None or len(gs) == dec)
        ok_all &= ok
        print(f"  {LABEL[r['arm']]:28} {r['entries']:16,} {100*(r['entries']-ref)/ref:+11.4f}% {len(gs):19d} "
              f"{'?' if dec is None else dec:>16}  {'ok' if ok else 'MISMATCH'}")
        for pc, kind, to in gs:
            print(f"  {'':28} guard site {pc} ({kind}) -> handler {to}")
        for e in r['ft']:
            print(f"  {'':28} fall-through {e['block_start']} -> handler {e['handler']}  x{e['count']:,}")
    print(f"  instrument canaries: {'PASS' if ok_all else 'FAIL -- the dispatch profile of a MISMATCH arm is not trustworthy'}")

print(f"\n  per-arm analysis in {out}/<arm>/ : vbb.mandelbrot.txt (block ranking),")
print( "    fig.bb_distributions.pdf, fig.pred_distributions.pdf, bbpair/pairs CSVs;")
print( "    <bundle>/out/lua.dispatch_stats.sites.csv lists every dispatch site (PC, jr/br)")
print( "\n  CAVEAT: the deltas above compare whole binaries. Inserting a guard also")
print( "    re-lays-out the interpreter, and that layout term was measured at +2.41%")
print( "    on this target. Attributing the delta to the guard alone requires the")
print( "    layout-matched control (see lua-mulmul-gt127, GUARD_TARGET=127).")
EOP
fi
say "done"
