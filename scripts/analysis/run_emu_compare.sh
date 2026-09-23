#!/usr/bin/env bash
# Reference clock vs TNT+CYC (n=6) emulated clock, for the three mandelbrot arms.
# Inputs are the bundle decodes: out/ (reference) and out-emu-tnt6/ (emulated), both
# produced from the same trace by the same decoder. Writes everything to output_emu_mandelbrot/.
set -euo pipefail
cd "$(dirname "$0")/../.."
PY=/scratch/iansseijelly/tacit-chipyard/.conda-env/bin/python3
S=scripts/analysis
OUT=output_emu_mandelbrot
mkdir -p "$OUT"
LABEL="sparse TNT+CYC n6"

# arm | bundle | optab | window s | blocks for the bb section
ARMS=(
  "base|lua-fuse-base-mandelbrot-20260901|lua_optab_fusebase.json|6.548791|0x21600,0x21560,0x21668,0x215c8"
  "mulmul|lua-fuse-mulmul-mandelbrot-20260903|lua_optab_mulmul.json|5.942725|0x1ffcc,0x1ffce,0x201ba,0x2003c"
  "mmadd|lua-fuse-mmadd-mandelbrot-20260903|lua_optab_mulmul_muladd.json|5.198005|0x1ffcc,0x1ffce,0x2006c,0x20044"
)

for spec in "${ARMS[@]}"; do
  IFS='|' read -r arm b optab win blocks <<< "$spec"
  B=bundles/$b
  [ -s "$B/out-emu-tnt6/lua.dispatch_stats.csv" ] || { echo "skip $arm: no emulated decode yet"; continue; }
  echo "== $arm"
  $PY $S/compare_emulated_dispatch.py --optab configs/lua/$optab \
      --ref "$B/out/lua.dispatch_stats.csv" --ref-hist "$B/out/lua.dispatch_hist.csv" \
      --emu "$B/out-emu-tnt6/lua.dispatch_stats.csv" --emu-hist "$B/out-emu-tnt6/lua.dispatch_hist.csv" \
      --window "$win" --label "$LABEL" \
      --bb-ref "$B/out/lua.bb_stats.csv" --bb-emu "$B/out-emu-tnt6/lua.bb_stats.csv" \
      $( [ -f "$B/out/lua.bb_hist.csv" ] && echo --bb-ref-hist "$B/out/lua.bb_hist.csv" ) \
      --bb-emu-hist "$B/out-emu-tnt6/lua.bb_hist.csv" --blocks "$blocks" \
      --out "$OUT/compare.$arm" > /dev/null
  # the same entry block under two clocks, side by side, as the AE grid draws it
  $PY $S/plot_pred_grid.py --targets MUL,ADD --row-height 44 --out "$OUT/fig.pred_grid.$arm" \
      "reference=$B/out/lua.dispatch_hist.csv:configs/lua/$optab" \
      "$LABEL=$B/out-emu-tnt6/lua.dispatch_hist.csv:configs/lua/$optab" > "$OUT/fig.pred_grid.$arm.log" 2>&1 || true
done

# guard selection from each clock's baseline profile (the step-2 tool of the loop, unchanged)
B=bundles/lua-fuse-base-mandelbrot-20260901
if [ -s "$B/out-emu-tnt6/lua.dispatch_stats.csv" ]; then
  echo "== guard selection, reference clock";  $PY $S/lua_select_fusion.py --optab configs/lua/lua_optab_fusebase.json \
      --bench mandelbrot="$B/out/lua.dispatch_stats.csv:6.548791" --max-guards 4 > "$OUT/select.ref.txt"
  echo "== guard selection, emulated clock";   $PY $S/lua_select_fusion.py --optab configs/lua/lua_optab_fusebase.json \
      --bench mandelbrot="$B/out-emu-tnt6/lua.dispatch_stats.csv:6.548791" --max-guards 4 > "$OUT/select.tnt6.txt"
fi

# whole-handler span (jr-to-jr), the sparse tracer's best case, if that decode exists.
# Guarded arrivals are canonicalised by the decoder (fall-through into the entry), so
# every arm uses its plain optab.
for spec in "base|lua-fuse-base-mandelbrot-20260901|lua_optab_fusebase.json|6.548791" \
            "mulmul|lua-fuse-mulmul-mandelbrot-20260903|lua_optab_mulmul.json|5.942725" \
            "mmadd|lua-fuse-mmadd-mandelbrot-20260903|lua_optab_mulmul_muladd.json|5.198005"; do
  IFS='|' read -r arm b optab win <<< "$spec"
  B=bundles/$b
  [ -s "$B/out-span/tnt6/lua.dispatch_stats.csv" ] || continue
  echo "== $arm, whole-handler span"
  $PY $S/compare_emulated_dispatch.py --optab configs/lua/$optab \
      --ref "$B/out-span/ref/lua.dispatch_stats.csv" --ref-hist "$B/out-span/ref/lua.dispatch_hist.csv" \
      --emu "$B/out-span/tnt6/lua.dispatch_stats.csv" --emu-hist "$B/out-span/tnt6/lua.dispatch_hist.csv" \
      --window "$win" --label "$LABEL" --miss-cyc 30 --out "$OUT/compare.span.$arm" > /dev/null
done
echo "done -> $OUT"

# the two figures: entry-block smear (base arm) and the guard breaking the handler span
B=bundles/lua-fuse-base-mandelbrot-20260901; M=bundles/lua-fuse-mulmul-mandelbrot-20260903
if [ -s "$B/out-span/tnt6/lua.dispatch_hist.csv" ]; then
  $PY $S/plot_smear_effects.py entry --optab configs/lua/lua_optab_fusebase.json \
      --entry-ref "$B/out/lua.dispatch_hist.csv" --entry-emu "$B/out-emu-tnt6/lua.dispatch_hist.csv" \
      --span-ref "$B/out-span/ref/lua.dispatch_hist.csv" --span-emu "$B/out-span/tnt6/lua.dispatch_hist.csv" \
      --targets MUL,ADD --out "$OUT/fig.smear_entry"
fi
MM=bundles/lua-fuse-mmadd-mandelbrot-20260903
if [ -s "$M/out-span/tnt6/lua.dispatch_hist.csv" ]; then
  ARMS3=("unguarded baseline=$B/out-span/ref/lua.dispatch_hist.csv:$B/out-span/tnt6/lua.dispatch_hist.csv:configs/lua/lua_optab_fusebase.json"
         "one guard, MUL->MUL=$M/out-span/ref/lua.dispatch_hist.csv:$M/out-span/tnt6/lua.dispatch_hist.csv:configs/lua/lua_optab_mulmul.json:2")
  [ -s "$MM/out-span/tnt6/lua.dispatch_hist.csv" ] && ARMS3+=("two guards, MUL->MUL and MUL->ADD=$MM/out-span/ref/lua.dispatch_hist.csv:$MM/out-span/tnt6/lua.dispatch_hist.csv:configs/lua/lua_optab_mulmul_muladd.json:2+3")
  $PY $S/plot_smear_effects.py span --target MUL --preds MUL,LTI,LEI,MULK --out "$OUT/fig.smear_span" "${ARMS3[@]}"
fi
# the same edge split by bytecode site (needs the span decodes with seq_path): the
# reference bimodality is two sites; the sparse clock hides it with one guard and
# invents a mode with two
SITES=()
for spec in "unguarded baseline|$B|lua_optab_fusebase.json" "one guard, MUL->MUL|$M|lua_optab_mulmul.json" \
            "two guards, MUL->MUL and MUL->ADD|$MM|lua_optab_mulmul_muladd.json"; do
  IFS='|' read -r lbl bd optab <<< "$spec"
  [ -s "$bd/out-span/tnt6/lua.dispatch_seq.csv" ] && SITES+=("$lbl=$bd/out-span/ref/lua.dispatch_seq.csv:$bd/out-span/tnt6/lua.dispatch_seq.csv:configs/lua/$optab")
done
if [ ${#SITES[@]} -ge 2 ]; then
  $PY $S/plot_smear_effects.py sites --edge MUL,MUL --out "$OUT/fig.site_split" \
      --site-names "ADD=pc 40 zi*zi, then ADD;SUB=pc 48 zi*zi, then SUB" "${SITES[@]}"
  for spec in "${SITES[@]}"; do
    lbl=${spec%%=*}; rest=${spec#*=}; IFS=':' read -r rs es op <<< "$rest"
    $PY $S/lua_seq_context_spans.py --optab "$op" --seq "$rs" --edge MUL,MUL --label "$lbl (reference)"
    $PY $S/lua_seq_context_spans.py --optab "$op" --seq "$es" --edge MUL,MUL --label "$lbl (sparse)"
  done > "$OUT/site_split.txt"
fi
# the paper figure: one edge, the entry block on the reference clock vs the handler span
# under both clocks (two-guard arm). Panel (a) comes from the FULL-RUN bb_hist only; the
# guarded entry block must be listed in bb_stats' hist_bbs for that decode. No fallback to
# the bb_seq prefix here: a figure must not change its data source depending on which files
# happen to exist.
if [ -s "$MM/out-span/tnt6/lua.dispatch_hist.csv" ]; then
  if grep -q "^0x1ffcc-" "$MM/out/lua.bb_hist.csv" 2>/dev/null; then
    $PY $S/plot_smear_effects.py edge --optab configs/lua/lua_optab_mulmul_muladd.json --edge MUL,MUL \
        --bb-hist "$MM/out/lua.bb_hist.csv" --entry-block 0x1ffcc \
        --span-ref "$MM/out-span/ref/lua.dispatch_hist.csv" \
        --span-emu "$MM/out-span/tnt6/lua.dispatch_hist.csv" --xmax 22 --height 46 --out "$OUT/fig.edge_mulmul"
  else
    echo "skip fig.edge_mulmul: 0x1ffcc not in $MM/out/lua.bb_hist.csv -- add it to bb_stats hist_bbs and re-decode"
  fi
fi
# one typical inner-loop iteration, event by event, under both clocks (replays the
# emulator over the bb_seq dump and checks it against the decoder's emulated dispatch_seq)
if [ -s "$MM/out-span/ref/lua.bb_seq.csv" ]; then
  $PY $S/lua_smear_trace.py --optab configs/lua/lua_optab_mulmul_muladd.json \
      --bb-seq "$MM/out-span/ref/lua.bb_seq.csv" --emu-seq "$MM/out-span/tnt6/lua.dispatch_seq.csv" \
      --nrows 3000000 --csv "$OUT/smear_trace.mmadd.csv" --fig "$OUT/fig.smear_trace" > "$OUT/smear_trace.mmadd.txt"
fi
# one handler, all predecessors, entry block vs span on the accurate clock (base arm)
if [ -s "$B/out-span/ref/lua.dispatch_hist.csv" ]; then
  $PY $S/plot_smear_effects.py unit --optab configs/lua/lua_optab_fusebase.json \
      --entry-hist "$B/out/lua.dispatch_hist.csv" --span-hist "$B/out-span/ref/lua.dispatch_hist.csv" \
      --target MUL --xmax-entry 22 --xmax-span 36 --out "$OUT/fig.unit_mul" > "$OUT/unit_mul.txt"
fi
# the same view after the first guard (one-guard arm)
if [ -s "$M/out-span/ref/lua.dispatch_hist.csv" ]; then
  $PY $S/plot_smear_effects.py unit --optab configs/lua/lua_optab_mulmul.json \
      --entry-hist "$M/out/lua.dispatch_hist.csv" --span-hist "$M/out-span/ref/lua.dispatch_hist.csv" \
      --target MUL --xmax-entry 22 --xmax-span 36 --out "$OUT/fig.unit_mul_mulmul" > "$OUT/unit_mul_mulmul.txt"
fi
# the discovery argument, no emulation needed: on the unfused interpreter a jalr-stamped
# tracer measures whole-handler spans exactly, so "rank by span excess" is its best signal;
# compare it with the entry-block ranking on every baseline capture that has both units
for spec in "mandelbrot|6.548791" "fannkuch|4.338237" "spectralnorm|7.066305" "sieve|4.670360"; do
  IFS='|' read -r bench win <<< "$spec"; bd=bundles/lua-fuse-base-$bench-20260901
  [ -s "$bd/out-span/ref/lua.dispatch_stats.csv" ] && [ -s "$bd/out/lua.dispatch_stats.csv" ] && \
    $PY $S/lua_span_vs_entry.py --optab configs/lua/lua_optab_fusebase.json --entry "$bd/out/lua.dispatch_stats.csv" \
        --span "$bd/out-span/ref/lua.dispatch_stats.csv" --window "$win" --label "$bench" --top 10 > "$OUT/span_vs_entry.$bench.txt"
done
# per-block attribution of the site difference, if a bb_seq dump exists (config.bbseq.json;
# the dump is ~3 GB per arm and is not produced by default)
for spec in "base|$B|lua_optab_fusebase.json" "mulmul|$M|lua_optab_mulmul.json" "mmadd|$MM|lua_optab_mulmul_muladd.json"; do
  IFS='|' read -r arm bd optab <<< "$spec"
  [ -s "$bd/out-span/ref/lua.bb_seq.csv" ] && \
    $PY $S/lua_site_block_breakdown.py --optab configs/lua/$optab --seq "$bd/out-span/ref/lua.bb_seq.csv" \
        --from MUL --to MUL --nrows 20000000 --min-share 0.05 > "$OUT/site_blocks.$arm.txt"
done
