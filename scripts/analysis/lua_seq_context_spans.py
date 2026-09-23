#!/usr/bin/env python3
"""Handler spans from the entry sequence, conditioned on deeper context than one predecessor.

`dispatch_stats` keys a handler's span on the handler before it. mandelbrot's inner loop
contains the same (from -> to) edge at two different bytecode sites, so a bimodal span may
be two sites, not one site varying. The dispatch_seq stream (entry timestamp, handler) lets
us split an edge by the handler two back and by the handler that follows, which pins each
arrival to its site in the loop.

  lua_seq_context_spans.py --optab configs/lua/lua_optab_mulmul_muladd.json \
      --seq bundles/<b>/out-span/ref/lua.dispatch_seq.csv --edge MUL,MUL [--label reference]
"""
import argparse
import json

import numpy as np
import pandas as pd


def modes(v, k=4, min_share=0.02):
    c = pd.Series(v).value_counts()
    n = c.sum()
    top = c[c / n >= min_share].sort_index().head(k)
    return ' '.join(f'{int(x)}c:{100*y/n:.0f}%' for x, y in top.items())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--optab', required=True)
    ap.add_argument('--seq', required=True)
    ap.add_argument('--edge', required=True, help='FROM,TO opcode names')
    ap.add_argument('--label', default='')
    ap.add_argument('--max-span', type=int, default=200, help='drop spans above this (trap/reset gaps)')
    a = ap.parse_args()
    tab = {int(k, 16): v for k, v in json.load(open(a.optab)).items()}
    f_op, t_op = [x.strip() for x in a.edge.split(',')]

    d = pd.read_csv(a.seq)
    ts = d['timestamp'].to_numpy(np.int64)
    h = d['to_handler'].map(lambda s: tab.get(int(s, 16), '?')).to_numpy()
    span = np.diff(ts)                       # span of entry i = ts[i+1] - ts[i]
    h0, h1, h2, h3 = h[:-3], h[1:-2], h[2:-1], h[3:]   # prev2, prev, this, next
    sp = span[2:]                            # span of entry i, aligned with h2 (i = 2..N-2)
    sel = (h1 == f_op) & (h2 == t_op) & (sp <= a.max_span)
    print(f'{a.label or a.seq}: {t_op} entered from {f_op}: {sel.sum():,} arrivals in the sequence prefix')
    print(f"  all           n={sel.sum():>10,}  mean {sp[sel].mean():6.2f}   modes {modes(sp[sel])}")
    print('  by handler two back (prev2 -> FROM -> TO):')
    for p2, g in pd.Series(sp[sel]).groupby(h0[sel]):
        if len(g) / sel.sum() >= 0.01:
            print(f"    {p2:>8} -> {f_op} -> {t_op}       n={len(g):>10,}  mean {g.mean():6.2f}   modes {modes(g)}")
    print('  by what follows (FROM -> TO -> next):')
    for nx, g in pd.Series(sp[sel]).groupby(h3[sel]):
        if len(g) / sel.sum() >= 0.01:
            print(f"    {f_op} -> {t_op} -> {nx:<8}       n={len(g):>10,}  mean {g.mean():6.2f}   modes {modes(g)}")
    print('  by both:')
    key = pd.Series([f'{p} .. {n}' for p, n in zip(h0[sel], h3[sel])])
    for k, g in pd.Series(sp[sel]).groupby(key.to_numpy()):
        if len(g) / sel.sum() >= 0.01:
            print(f"    {k:>18}       n={len(g):>10,}  mean {g.mean():6.2f}   modes {modes(g)}")


if __name__ == '__main__':
    main()
