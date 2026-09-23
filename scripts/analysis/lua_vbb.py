#!/usr/bin/env python3
"""vbb: rank every basic block in a capture by how much its execution time varies.

Same quantity trace_db_tools bb-stats reports (count, mean, netvar, bb), computed from the
bb_stats receiver CSV so no sqlite DB is needed. This is the workload-agnostic first pass:
no symbols, no source, no interpreter model -- just "which blocks vary".

Optionally cross-references the jump table (--optab) to mark which of the top blocks are
bytecode handler entry points, which is the step that turns a ranking into a diagnosis.

  lua_vbb.py trace.lua-fuse-base-mandelbrot.bb_stats.csv --optab configs/lua/lua_optab_fusebase.json \
      --out output_lua_scratch/vbb.mandelbrot
"""
import argparse
import json

import pandas as pd


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('bb_stats_csv')
    ap.add_argument('--optab')
    ap.add_argument('--out', required=True, help='prefix: writes <out>.csv and <out>.txt')
    ap.add_argument('--top', type=int, default=25)
    a = ap.parse_args()

    d = pd.read_csv(a.bb_stats_csv, skipinitialspace=True)
    d['bb'] = d['bb'].str.strip()
    d['start'] = d['bb'].str.split('-').str[0]
    d['user'] = ~d['start'].str.lower().str.startswith('0xffffffff')
    if a.optab:
        tab = {k.lower(): v for k, v in json.load(open(a.optab)).items()}
        d['handler'] = d['start'].str.lower().map(tab).fillna('')
    else:
        d['handler'] = ''
    # Rank on vbb = n*(mean-p5): cycles above the block's near-best case, i.e. the time
    # attributable to microarchitectural variation rather than to the block's own work.
    # The floor is p5, not min: min is a single luckiest sample and moves ~10% between
    # identical runs. The receiver emits `vbb` directly (exact, since histogram bins are
    # one cycle wide); older CSVs are handled by recomputing it from mean and p5.
    if 'vbb' not in d.columns:
        floor = d['p5'] if 'p5' in d.columns else d['min']
        d['vbb'] = d['count'] * (d['mean'] - floor).clip(lower=0)
    d = d.sort_values('vbb', ascending=False).reset_index(drop=True)
    d['rank'] = d.index + 1
    tot = d['vbb'].sum()
    d['share'] = d['vbb'] / tot
    d['cum_share'] = d['share'].cumsum()

    cols = [c for c in ['rank', 'bb', 'handler', 'count', 'mean', 'min', 'p5', 'p25',
                        'p50', 'p90', 'p99', 'max', 'netvar', 'vbb', 'share', 'cum_share']
            if c in d.columns]
    d[cols].to_csv(f'{a.out}.csv', index=False, float_format='%.4f')

    top = d.head(a.top)
    lines = [
        '=' * 72,
        f'vbb — basic blocks ranked by n*(mean-p5)   ({a.bb_stats_csv})',
        '=' * 72,
        f'blocks: {len(d):,}    total vbb (n*(mean-p5)): {tot/1e9:.3f} Gcyc',
        f'top 10 blocks hold {100*d.head(10)["share"].sum():.1f}% of it; '
        f'top 20 hold {100*d.head(20)["share"].sum():.1f}%',
    ]
    if a.optab:
        h = top[top.handler != '']
        lines.append(f'of the top {a.top}, {len(h)} are bytecode handler entry blocks, '
                     f'holding {100*h["share"].sum():.1f}% of all variation')
    lines += ['', f"{'rank':>4} {'basic block':24} {'handler':>10} {'executions':>13} "
                  f"{'p5':>5} {'p25':>5} {'p50':>5} {'p90':>5} {'p99':>5} "
                  f"{'vbb Mcyc':>10} {'abs%':>6} {'cum%':>6}"]
    for r in top.itertuples():
        p5 = getattr(r, 'p5', float('nan'))
        p25 = getattr(r, 'p25', float('nan'))
        p99 = getattr(r, 'p99', float('nan'))
        lines.append(f'{r.rank:4d} {r.bb:24} {r.handler:>10} {int(r.count):13,d} '
                     f'{p5:5.0f} {p25:5.0f} {r.p50:5.0f} {r.p90:5.0f} {p99:5.0f} '
                     f'{r.vbb/1e6:10.1f} {100*r.share:5.1f}% {100*r.cum_share:5.1f}%')
    txt = '\n'.join(lines) + '\n'
    open(f'{a.out}.txt', 'w').write(txt)
    print(txt)
    print(f'wrote {a.out}.csv and {a.out}.txt')
    print('Ranked by vbb = n*(mean-p5): cycles above the block near-best case. '
          'p5 not min, since min is one lucky sample; both exact from 1-cycle bins.')


if __name__ == '__main__':
    main()
