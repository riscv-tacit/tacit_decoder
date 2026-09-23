#!/usr/bin/env python3
"""Assemble a self-contained per-run artifact bundle from a FireSim results
directory. The bundle carries everything a decode needs -- encoded trace,
oracle outputs, uartlog, kernel/driver/app binaries, and a decoder config
with bundle-relative paths -- so it never goes stale when live trees are
rebuilt.

Module addresses in driver_binary_entry_tuples are not assumed: they are
parsed from the run's own uartlog (the ::MODULES_BEGIN::/::MODULES_END::
block emitted by the firemarshal init script), i.e. measured provenance.

Layout:
  bundle/
    config.json            decoder config, paths relative to bundle root
    manifest.json          source paths, git SHAs, timestamps
    uartlog
    trace/tacit0.out
    oracle/bboracle*.csv[.zst] bbtrace.txt ...
    binaries/machine-bin binaries/kernel-dwarf     (linux runs)
    binaries/drivers/<name>-dwarf                  (linux runs)
    binaries/app/<elf>
    provenance/HW_CFG_SUMMARY sim-run.sh ...
    out/                   analysis products (analyze_capture.py writes here)

Usage:
  bundle_run.py --results RESULTS_JOB_DIR --template TEMPLATE_JSON --out BUNDLE
                [--app ELF]... [--image FIREMARSHAL_IMAGE_DIR] [--tar]

Linux mode (--image given): machine_binary/kernel_binary point at the
image's own -bin/-bin-dwarf, tuples are built from the image's per-driver
dwarf snapshots with addresses from the uartlog. Baremetal mode: the first
--app ELF becomes machine_binary.
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ORACLE_GLOBS = ["bboracle*", "bbtrace*", "insttrace*", "oracle*", "tokens*"]
PROVENANCE_FILES = ["HW_CFG_SUMMARY", "sim-run.sh", "memory_stats.csv"]
MODULES_RX = re.compile(
    r"^(\w+) \d+ \d+ \S+ Live (0x[0-9a-f]+)", re.MULTILINE)
# trace-submit drains the driver's task log and prints one line per traced
# task; comm is the kernel task name (binary basename truncated to 15 chars)
ASID_RX = re.compile(r"tacit: asid=(\d+) pid=\d+ comm=(\S+)")


def die(msg):
    sys.exit(f"bundle_run: ERROR: {msg}")


def parse_uartlog_modules(uartlog):
    """Return {module_name: text_base} from the init script's sentinel block
    (falls back to scanning the whole log for /proc/modules-format lines)."""
    text = uartlog.read_text(errors="replace").replace("\r", "")
    m = re.search(r"::MODULES_BEGIN::\n(.*?)::MODULES_END::", text, re.DOTALL)
    scope = m.group(1) if m else text
    mods = {name: addr for name, addr in MODULES_RX.findall(scope)}
    if m and not mods:
        die("uartlog has a ::MODULES:: block but no parsable module lines")
    return mods


def parse_run_asids(res, uartlog, app_basename):
    """asids of traced tasks whose comm matches the app binary (comm is a
    truncated basename, so match by prefix). trace-submit prints these on
    stdout, which lands in the uartlog for console jobs and in the fetched
    output/*.out files for jobs whose stdout is redirected."""
    texts = [uartlog.read_text(errors="replace")]
    for f in sorted((res / "output").glob("*.out")) if (res / "output").is_dir() else []:
        texts.append(f.read_text(errors="replace"))
    asids = []
    for text in texts:
        for asid, comm in ASID_RX.findall(text.replace("\r", "")):
            if len(comm) >= 3 and app_basename.startswith(comm):
                asids.append(int(asid))
    return sorted(set(asids))


def disptab_handlers(elf_path):
    """Handler entry addresses read out of the app ELF's own computed-goto table.

    A bytecode interpreter's dispatch targets are build-specific: every rebuild moves all
    of them. Recording them in a template guarantees they eventually disagree with the
    binary sitting next to them, so derive them from the bundled ELF instead -- the same
    reason asids and driver bases are parsed from the uartlog rather than written down.
    Returns [] if this app has no such table (not an interpreter, or a stripped binary).
    """
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return []
    import struct
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        sym = None
        for sec in elf.iter_sections():
            if sec.header["sh_type"] != "SHT_SYMTAB":
                continue
            for cand in sec.iter_symbols():
                if re.fullmatch(r"disptab(\.\d+)?", cand.name):
                    sym = cand
        if sym is None:
            return []
        addr, size = sym["st_value"], sym["st_size"]
        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            lo, hi = seg["p_vaddr"], seg["p_vaddr"] + seg["p_filesz"]
            if lo <= addr and addr + size <= hi:
                raw = seg.data()[addr - lo: addr - lo + size]
                ptrs = struct.unpack("<%dQ" % (size // 8), raw)
                return [hex(p) for p in sorted(set(ptrs))]
    return []


def git_info(path):
    def run(*cmd):
        try:
            return subprocess.run(["git", "-C", str(path)] + list(cmd),
                                  capture_output=True, text=True,
                                  timeout=10).stdout.strip()
        except Exception:
            return ""
    sha = run("rev-parse", "HEAD")
    if not sha:
        return None
    return {"sha": sha, "dirty": bool(run("status", "--porcelain"))}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True, type=Path,
                    help="per-job results dir (contains tacit0.out, uartlog)")
    ap.add_argument("--template", required=True, type=Path,
                    help="decoder config template (analytical intent only)")
    ap.add_argument("--out", required=True, type=Path, help="bundle dir")
    ap.add_argument("--app", action="append", default=[], type=Path,
                    help="application ELF (repeatable; first one is "
                         "machine_binary in baremetal mode)")
    ap.add_argument("--image", type=Path,
                    help="firemarshal image dir (enables Linux mode)")
    ap.add_argument("--jlmap", type=Path, default=None,
                    help="jump-label patch map when the job itself did not "
                         "capture one (e.g. produced by a chores job in the "
                         "same deterministic boot)")
    ap.add_argument("--tar", action="store_true",
                    help="also produce <out>.tar.zst")
    args = ap.parse_args()

    res, out = args.results, args.out
    if not res.is_dir():
        die(f"results dir {res} not found")
    if out.exists() and any(out.iterdir()):
        die(f"bundle dir {out} exists and is not empty")
    template = json.loads(args.template.read_text())

    for sub in ["trace", "oracle", "binaries/app", "provenance", "out"]:
        (out / sub).mkdir(parents=True, exist_ok=True)

    # --- results dir contents ---
    trace = res / "tacit0.out"
    if not trace.exists():
        die(f"{trace} not found")
    shutil.copy2(trace, out / "trace/tacit0.out")

    uartlog = res / "uartlog"
    if not uartlog.exists():
        die(f"{uartlog} not found (needed for provenance)")
    shutil.copy2(uartlog, out / "uartlog")

    oracle_files = []
    for pat in ORACLE_GLOBS:
        for f in sorted(res.glob(pat)):
            shutil.copy2(f, out / "oracle" / f.name)
            oracle_files.append(f.name)
    if not oracle_files:
        print("bundle_run: WARNING: no oracle outputs found in results dir")

    for name in PROVENANCE_FILES:
        if (res / name).exists():
            shutil.copy2(res / name, out / "provenance" / name)
    if (res / "output").is_dir():  # fetched guest /output (asid lines etc.)
        shutil.copytree(res / "output", out / "provenance/output",
                        dirs_exist_ok=True)

    # jump-label patch map: boot-time kernel code patches the decoder must
    # know about; the job captures it into /output which firesim fetches
    jlmap = None
    cands = [res / "jump_label_patch_map.txt",
             res / "output/jump_label_patch_map.txt"]
    if args.jlmap:
        cands.insert(0, args.jlmap)
    for cand in cands:
        if cand.exists():
            jlmap = cand
            break
    has_jlmap = jlmap is not None
    if has_jlmap:
        shutil.copy2(jlmap, out / "provenance/jump_label_patch_map.txt")

    # --- config: template carries intent, we wire provenance ---
    cfg = dict(template)
    cfg["encoded_trace"] = "trace/tacit0.out"

    apps = []
    for app in args.app:
        if not app.exists():
            die(f"app binary {app} not found")
        shutil.copy2(app, out / "binaries/app" / app.name)
        apps.append(f"binaries/app/{app.name}")

    if args.image:
        img = args.image
        name = img.name
        bin_ = img / f"{name}-bin"
        dwarf = img / f"{name}-bin-dwarf"
        for f in (bin_, dwarf):
            if not f.exists():
                die(f"{f} not found in image dir")
        shutil.copy2(bin_, out / "binaries/machine-bin")
        shutil.copy2(dwarf, out / "binaries/kernel-dwarf")
        cfg["machine_binary"] = "binaries/machine-bin"
        cfg["kernel_binary"] = "binaries/kernel-dwarf"
        if has_jlmap:
            cfg["kernel_jump_label_patch_log"] = \
                "provenance/jump_label_patch_map.txt"
        elif cfg.get("kernel_jump_label_patch_log"):
            die("template expects a jump-label patch map but the results "
                "dir has no jump_label_patch_map.txt")

        mods = parse_uartlog_modules(uartlog)
        if not mods:
            die("Linux mode but uartlog has no /proc/modules lines -- "
                "was the image built with the pinned-modprobe init script?")
        (out / "binaries/drivers").mkdir(exist_ok=True)
        tuples = []
        driver_dwarfs = sorted(p for p in img.glob("*-dwarf")
                               if not p.name.endswith("-bin-dwarf"))
        if not driver_dwarfs:
            die(f"no per-driver dwarfs in {img} -- rebuild the image "
                "(build.py driver-dwarf emission)")
        for d in driver_dwarfs:
            mod = d.name[:-len("-dwarf")]
            if mod not in mods:
                die(f"driver '{mod}' has a dwarf in the image but no "
                    f"address in uartlog /proc/modules ({sorted(mods)})")
            shutil.copy2(d, out / "binaries/drivers" / d.name)
            tuples.append([f"binaries/drivers/{d.name}", mods[mod]])
        cfg["driver_binary_entry_tuples"] = tuples

        if len(apps) != len(cfg.get("user_binaries", [])):
            die(f"template declares {len(cfg.get('user_binaries', []))} "
                f"user_binaries but {len(apps)} --app given")
        ub = []
        for entry, rel in zip(cfg.get("user_binaries", []), apps):
            e = dict(entry)
            e["binary"] = rel
            measured = parse_run_asids(res, uartlog, Path(rel).name)
            if measured:
                if e.get("asids") and sorted(e["asids"]) != measured:
                    print(f"bundle_run: asids for {Path(rel).name}: "
                          f"template {e['asids']} -> measured {measured}")
                e["asids"] = measured
            elif not e.get("asids"):
                die(f"no asids in template and none measured in uartlog "
                    f"for {Path(rel).name}")
            else:
                print(f"bundle_run: WARNING: no 'tacit: asid=' lines for "
                      f"{Path(rel).name} in uartlog; keeping template "
                      f"asids {e['asids']}")
            ub.append(e)
        cfg["user_binaries"] = ub
    else:
        if not apps:
            die("baremetal mode needs at least one --app")
        cfg["machine_binary"] = apps[0]
        cfg.setdefault("kernel_binary", "")
        cfg.setdefault("user_binaries", [])
        cfg.setdefault("driver_binary_entry_tuples", [])

    for recv, rcfg in cfg.get("receivers", {}).items():
        if not isinstance(rcfg, dict):
            continue
        # "handlers": "from-disptab" -> read the dispatch table out of a bundled app ELF,
        # so the handler list cannot disagree with the binary shipped beside it
        if rcfg.get("handlers") == "from-disptab":
            found = []
            for rel in apps:
                found = disptab_handlers(out / rel)
                if found:
                    print(f"bundle_run: {recv}: {len(found)} handlers read from {rel}")
                    break
            if not found:
                die(f"{recv} asked for handlers from disptab but no bundled app has one")
            rcfg["handlers"] = found
        # every output key, not just "path": a receiver that writes elsewhere (hist_path,
        # seq_path) would otherwise scatter files outside the bundle
        for key in ("path", "hist_path", "seq_path"):
            if isinstance(rcfg.get(key), str) and rcfg[key]:
                rcfg[key] = f"out/{Path(rcfg[key]).name}"
        cfg["receivers"][recv] = rcfg

    (out / "config.json").write_text(json.dumps(cfg, indent=2) + "\n")

    # --- manifest ---
    here = Path(__file__).resolve()
    decoder_root = here.parents[2]
    top = decoder_root.parents[1]
    manifest = {
        "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "results_dir": str(res.resolve()),
        "image_dir": str(args.image.resolve()) if args.image else None,
        "template": str(args.template.resolve()),
        "apps": [str(a.resolve()) for a in args.app],
        "oracle_files": oracle_files,
        "git": {name: git_info(p) for name, p in {
            "tacit-chipyard": top,
            "firemarshal": top / "software/firemarshal",
            "tacit_decoder": decoder_root,
            "firesim": top / "sims/firesim",
            "boom": top / "generators/boom",
        }.items()},
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    print(f"bundle_run: bundle assembled at {out}")
    if args.tar:
        tarball = out.with_suffix(".tar.zst")
        subprocess.run(["tar", "--zstd", "-cf", str(tarball),
                        "-C", str(out.parent), out.name], check=True)
        print(f"bundle_run: wrote {tarball}")


if __name__ == "__main__":
    main()
