#!/usr/bin/env python3
"""Paired-BB view: for the blocks that vary most, is the variation set by the predecessor?

vbb ranks blocks by span with no notion of handlers. This takes that ranking and, for each
top block, breaks its latency down by the block that ran immediately before it. It needs no
jump table and no interpreter model -- the same question the dispatch analysis asks, but
asked generically, so the answer is not an artefact of knowing what Lua is.

  lua_bb_pair_view.py --bb-stats <bb_stats.csv> --bb-pairs <bb_pair_stats.csv> \
      --optab <optab.json> --out output_mandelbrot/bbpair.mandelbrot --top 8
"""
import argparse
import json

import pandas as pd


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bb-stats', required=True)
    ap.add_argument('--bb-pairs', required=True)
    ap.add_argument('--optab')
    ap.add_argument('--out', required=True)
    ap.add_argument('--top', type=int, default=8)
    ap.add_argument('--min-n', type=int, default=10000)
    a = ap.parse_args()

    tab = {k.lower(): v for k, v in json.load(open(a.optab)).items()} if a.optab else {}
    b = pd.read_csv(a.bb_stats, skipinitialspace=True)
    b['bb'] = b['bb'].str.strip()
    b['span'] = b['vbb'] if 'vbb' in b.columns else (b['spread'] if 'spread' in b.columns else b['count']*(b['p90']-b['p50']))
    b = b.sort_values('span', ascending=False)

    p = pd.read_csv(a.bb_pairs, skipinitialspace=True)
    for c in ('prev_bb', 'bb'):
        p[c] = p[c].str.strip()
    p['prev_start'] = p['prev_bb'].str.split('-').str[0]
    p['handler_prev'] = p['prev_start'].str.lower().map(tab).fillna('')

    rows, lines = [], []
    for t in b.head(a.top).itertuples():
        sub = p[(p.bb == t.bb) & (p['count'] >= a.min_n)].sort_values('count', ascending=False)
        if len(sub) < 1:
            continue
        h = tab.get(t.bb.split('-')[0].lower(), '')
        lines.append(f"\n{t.bb}{('  [' + h + ' entry]') if h else ''}"
                     f"   n={int(t.count):,}  p25={t.p25:.0f} p50={t.p50:.0f} p90={t.p90:.0f}"
                     f"  span={t.span/1e6:.0f}M")
        lines.append(f"    {'previous block':24} {'via':>10} {'n':>12} {'p50':>5} {'p90':>5} {'mean':>7}")
        for r in sub.head(6).itertuples():
            lines.append(f"    {r.prev_bb:24} {r.handler_prev:>10} {int(r.count):12,d} "
                         f"{r.p50:5.0f} {r.p90:5.0f} {r.mean:7.2f}")
            rows.append(dict(bb=t.bb, handler=h, prev_bb=r.prev_bb,
                             prev_handler=r.handler_prev, n=int(r.count),
                             p50=r.p50, p90=r.p90, mean=r.mean))
        spread = sub.head(6)['p50'].max() - sub.head(6)['p50'].min()
        lines.append(f"    -> p50 across predecessors spans {spread:.0f} cycles"
                     + ("  (predecessor-determined)" if spread >= 5 else "  (predecessor-independent)"))

    pd.DataFrame(rows).to_csv(f'{a.out}.csv', index=False, float_format='%.3f')
    txt = ("paired-BB view: top blocks by span, decomposed by the block that ran before\n"
           + '=' * 78 + '\n' + '\n'.join(lines) + '\n')
    open(f'{a.out}.txt', 'w').write(txt)
    print(txt)
    print(f'wrote {a.out}.csv and {a.out}.txt')


if __name__ == '__main__':
    main()
