#!/usr/bin/env python3
"""Predictability of the handler stream at increasing history depth.

For each capture, the share of transitions whose next handler equals the modal successor
of the k-deep handler history. order-1 is the ceiling for one BTB entry per dispatch site
(what the -fno-crossjumping baseline gives); order-2+ is what a history-indexed predictor
-- or a guard, which is a conditional branch -- can reach. `live ctx` counts histories that
actually occur, i.e. how many specialised handler copies would be needed.

  lua_stream_order.py --optab configs/lua/lua_optab_fusebase.json \
      --seq mandelbrot=trace.lua-fuse-base-mandelbrot.dispatch_seq.csv
"""
import argparse
import json

import numpy as np
import pandas as pd


def modal(hist, nxt, K):
    key = hist * K + nxt
    cnt = np.bincount(key)
    nz = np.nonzero(cnt)[0]
    ctx = nz // K
    mx = np.zeros(int(ctx.max()) + 1, dtype=np.int64)
    np.maximum.at(mx, ctx, cnt[nz])
    return mx.sum() / cnt.sum(), int(np.count_nonzero(np.bincount(hist)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--optab', required=True)
    ap.add_argument('--seq', action='append', required=True, metavar='NAME=CSV')
    ap.add_argument('--depth', type=int, default=4)
    ap.add_argument('--check', action='append', default=[], metavar='NAME=DISPATCH_STATS_CSV',
                    help='full-run dispatch_stats to validate the seq PREFIX against: '
                         'dispatch_seq is capped at seq_limit events, so it is the first '
                         'N events, not a sample of the run.')
    a = ap.parse_args()
    optab = json.load(open(a.optab))
    full = {}
    for spec in a.check:
        name, csv = spec.split('=', 1)
        d = pd.read_csv(csv, skipinitialspace=True)
        for c in ('from_handler', 'to_handler'):
            d[c] = d[c].str.strip()
        d['f'] = d['from_handler'].map(optab); d['t'] = d['to_handler'].map(optab)
        d = d.dropna(subset=['f', 't'])
        g = d.groupby(['f', 't'])['count'].sum()
        full[name] = (g.groupby('f').max().sum() / g.sum(), int(g.sum()))

    print(f"{'bench':14s} {'events':>12s} {'alphabet':>9s} " +
          ' '.join(f'{"order-"+str(k):>8s}' for k in range(1, a.depth + 1)) +
          f" | {'live ctx o2':>11s} {'o3':>7s} | {'full-run o1':>11s} {'coverage':>9s}")
    for spec in a.seq:
        name, csv = spec.split('=', 1)
        c = pd.read_csv(csv, usecols=['to_handler'])['to_handler'].astype('category')
        v = c.cat.codes.to_numpy().astype(np.int64)
        K = len(c.cat.categories)
        n = len(v)
        del c
        shares, ctxs, h = [], [], None
        for k in range(1, a.depth + 1):
            h = v[:-k] if k == 1 else h[:-1] * K + v[k - 1:-1]
            s, nc = modal(h, v[k:], K)
            shares.append(s); ctxs.append(nc)
        tail = ''
        if name in full:
            o1_full, n_full = full[name]
            flag = '  <-- PREFIX NOT REPRESENTATIVE' if abs(o1_full - shares[0]) > 0.02 else ''
            tail = f' | {100*o1_full:10.1f}% {100*n/n_full:8.1f}%{flag}'
        print(f"{name:14s} {n:12,d} {K:9d} " + ' '.join(f'{100*s:7.1f}%' for s in shares) +
              f" | {ctxs[1]:11,d} {ctxs[2]:7,d}" + tail)
        del v, h


if __name__ == '__main__':
    main()
