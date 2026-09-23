#!/usr/bin/env python3
"""Generate decode configs for a lua-fuse capture (step 2/4 plumbing).

Reads the per-job uartlogs for the things that used to be hand-copied and silently rot:
the asid->binary map, the guest window (trace-run duration) and the guest program output.
Reads the chores job for the driver load addresses and the jump-label patch map.
Handler addresses come from the variant's own extracted optab.

  gen_lua_fuse_configs.py <results-workload-dir> --tag base \
      --optab configs/lua/lua_optab_fusebase.json [--seq-limit 40000000]

Writes configs/lua/lua_fuse_<tag>_<bench>.json plus a windows/correctness manifest.
Run from the tacit_decoder directory.
"""
import argparse
import json
import re
from pathlib import Path

CY = Path('/scratch/iansseijelly/tacit-chipyard')
FM = CY / 'software/firemarshal'


def read_uartlog(p):
    txt = p.read_bytes().decode('utf-8', 'replace').replace('\r', '')
    asids = {c: int(a) for a, c in re.findall(r'tacit: asid=(\d+) pid=\d+ comm=(\S+)', txt)}
    dur = re.search(r'duration ([\d.]+) s', txt)
    exitst = re.search(r'child exit status (\d+)', txt)
    body = txt.split('launching firemarshal workload run/command\n')[-1]
    # stop at the host-side simulator summary: it carries cycle counts, which legitimately
    # differ between variants and would otherwise break the guest-output invariant check
    body = body.split('Simulation complete.')[0]
    out = [l for l in body.split('\n')
           if l and not l.startswith(('trace-run:', 'tacit:', '[', 'Script done'))]
    return dict(asids=asids, window_s=float(dur.group(1)) if dur else None,
                child_exit=int(exitst.group(1)) if exitst else None,
                guest_output=out[:6])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('results')
    ap.add_argument('--tag', required=True)
    ap.add_argument('--optab', required=True)
    ap.add_argument('--seq-limit', type=int, default=40_000_000)
    ap.add_argument('--out-prefix', default='output_lua_scratch/trace.lua-fuse')
    ap.add_argument('--label', help='name for configs/CSVs of THIS capture '
                    '(default: --tag). Use it to keep repeat runs of the same '
                    'variant apart.')
    a = ap.parse_args()

    res = Path(a.results)
    wl = f'lua-fuse-{a.tag}'
    lab = a.label or a.tag
    optab = json.load(open(a.optab))
    handlers = sorted(optab, key=lambda x: int(x, 16))

    chores = res / f'{wl}-{a.tag}-chores'
    drivers = {}
    dm = chores / 'driver_map.txt'
    if dm.exists():
        for line in dm.read_bytes().decode('utf-8', 'replace').replace('\r', '').splitlines():
            f = line.split()
            if len(f) == 2:
                drivers[f[0]] = f[1]
    else:
        print(f'WARNING: {dm} missing -- kernel-side decode will be degraded')

    ovl = FM / f'example-workloads/{wl}/overlay/root/lua-dispatch'
    manifest = {'tag': a.tag, 'label': lab, 'results': str(res), 'jobs': {}}
    for job in sorted(res.glob(f'{wl}-{a.tag}-*-traced')):
        bench = job.name[len(f'{wl}-{a.tag}-'):-len('-traced')]
        info = read_uartlog(job / 'uartlog')
        if not info['asids']:
            print(f'WARNING {bench}: no asid map in uartlog; skipping')
            continue
        img = FM / f'images/firechip/{job.name}'
        cfg = {
            'encoded_trace': str(job / 'tacit0.out'),
            'user_binaries': [
                {'binary': str(ovl / 'lua'), 'asids': [info['asids']['lua']]},
                {'binary': str(ovl / 'trace-run'), 'asids': [info['asids']['trace-run']]},
            ],
            'machine_binary': str(img / f'{job.name}-bin'),
            'kernel_binary': str(img / f'{job.name}-bin-dwarf'),
            'kernel_jump_label_patch_log': str(chores / 'jump_label_patch_map.txt'),
            # Point at the IMAGE's per-driver dwarf snapshot, not the live build tree.
            # boards/.../drivers/*.o is rebuilt by any later `marshal build`, and decoding a
            # trace against a driver of a different vintage desyncs PC reconstruction
            # immediately (the trace starts inside the tacit driver). The image snapshot is
            # frozen at the time the image was built, which is the run's own vintage.
            'driver_binary_entry_tuples': [
                [str(img / f'{d}-dwarf'), drivers[d]]
                for d in ('tacit', 'iceblk', 'icenet')
                if d in drivers and (img / f'{d}-dwarf').exists()
            ],
            'receivers': {
                'prv_breakdown': {'enabled': True},
                'bb_stats': {'enabled': True, 'path': f'{a.out_prefix}-{lab}-{bench}.bb_stats.csv'},
                'bb_pair_stats': {'enabled': True,
                                  'path': f'{a.out_prefix}-{lab}-{bench}.bb_pair_stats.csv'},
                'dispatch_stats': {'enabled': True,
                                   'path': f'{a.out_prefix}-{lab}-{bench}.dispatch_stats.csv',
                                   'handlers': handlers,
                                   'seq_path': f'{a.out_prefix}-{lab}-{bench}.dispatch_seq.csv',
                                   'seq_limit': a.seq_limit},
            },
        }
        p = Path(f'configs/lua/lua_fuse_{lab}_{bench}.json')
        p.write_text(json.dumps(cfg, indent=1) + '\n')
        manifest['jobs'][bench] = dict(config=str(p), window_s=info['window_s'],
                                       child_exit=info['child_exit'],
                                       asids=info['asids'], guest_output=info['guest_output'],
                                       trace_bytes=(job / 'tacit0.out').stat().st_size
                                       if (job / 'tacit0.out').exists() else None)
        print(f"{bench:14s} window {info['window_s']}s  exit {info['child_exit']}  "
              f"asids {info['asids']}  -> {p}")

    mp = Path(f'configs/lua/lua_fuse_{lab}_manifest.json')
    mp.write_text(json.dumps(manifest, indent=1) + '\n')
    print(f'\nmanifest -> {mp}')
    print('guest output (check identical across variants):')
    for b, j in manifest['jobs'].items():
        print(f"  {b:14s} {' | '.join(j['guest_output'])[:100]}")


if __name__ == '__main__':
    main()
