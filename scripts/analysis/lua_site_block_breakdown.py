#!/usr/bin/env python3
"""Per-block latency of one handler's executions, split by bytecode site.

Input is the bb_seq stream (one row per executed basic block: timestamp when it ended,
start, end PC, kind of the arc that ended it). A handler execution is the run of blocks
from an arrival at its entry (or at a block that falls through into its entry) to the next
handler entry. The site is identified by the handler that follows.

For every block position on the handler's path, print the latency distribution per site,
so the question "which block carries the difference between the sites, and is the entry
block one of them" is answered from per-instance data rather than from pooled histograms.

  lua_site_block_breakdown.py --optab configs/lua/lua_optab_mulmul_muladd.json \
      --seq bundles/<b>/out-span/ref/lua.bb_seq.csv --from MUL --to MUL \
      --site-by next --min-share 0.05
"""
import argparse
import json
from collections import defaultdict

import numpy as np
import pandas as pd


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--optab', required=True)
    ap.add_argument('--seq', required=True)
    ap.add_argument('--from', dest='f_op', required=True)
    ap.add_argument('--to', dest='t_op', required=True)
    ap.add_argument('--min-share', type=float, default=0.03,
                    help='only report block paths taken by at least this share of instances')
    ap.add_argument('--max-blocks', type=int, default=16)
    ap.add_argument('--nrows', type=int, default=30_000_000,
                    help='block events to read from the head of the dump')
    ap.add_argument('--skiprows', type=int, default=0,
                    help='block events to skip first (a mid-run window avoids warm-up)')
    a = ap.parse_args()

    tab = {int(k, 16): v for k, v in json.load(open(a.optab)).items()}
    entries = sorted(tab)                              # handler entry addresses
    entry_arr = np.array(entries, dtype=np.int64)

    d = pd.read_csv(a.seq, dtype={'bb_end': str, 'kind': str}, nrows=a.nrows,
                    skiprows=range(1, a.skiprows + 1) if a.skiprows else None)
    ts = d['timestamp'].to_numpy(np.int64)
    M63 = (1 << 63) - 1          # kernel addresses (0xffffffff...) would overflow int64
    start = d['bb_start'].map(lambda s: int(s, 16) & M63).to_numpy(np.int64)
    end = d['bb_end'].map(lambda s: (int(s, 16) & M63) if isinstance(s, str) and s else -1).to_numpy(np.int64)
    kind = d['kind'].to_numpy()
    n = len(d)
    # block i: [start[i], end[i]], ran from ts[i-1] to ts[i]  (latency = ts[i]-ts[i-1])
    lat = np.empty(n, dtype=np.int64); lat[0] = 0; lat[1:] = np.diff(ts)

    # which handler does block i ENTER? exact start, or an entry strictly inside the block
    idx = np.searchsorted(entry_arr, start, side='left')
    exact = (idx < len(entry_arr)) & (entry_arr[np.minimum(idx, len(entry_arr) - 1)] == start)
    idx2 = np.searchsorted(entry_arr, start, side='right')          # first entry > start
    inside = (idx2 < len(entry_arr)) & (entry_arr[np.minimum(idx2, len(entry_arr) - 1)] <= end) & (end >= 0)
    enters = np.full(n, -1, dtype=np.int64)
    enters[exact] = entry_arr[idx[exact]]
    m = inside & ~exact
    enters[m] = entry_arr[idx2[m]]
    # mirror dispatch_stats exactly. The receiver steps only on branch/jump events; a trap,
    # sync or resume just resets the flow to its target. Hence:
    #  * an exact-start entry is counted only if the arc that landed on it was a branch/jump
    #    (a trap-return landing on a handler address is not an entry);
    #  * a contained (fall-through) entry is found when the block CLOSES with a branch/jump,
    #    whatever arc started the block, so a block cut short by a trap is never examined.
    reached_by_cfi = np.zeros(n, dtype=bool)
    reached_by_cfi[1:] = ~np.isin(kind[:-1], ('trap', 'sync', 'resume'))
    cut_by_trap = np.isin(kind, ('trap', 'sync', 'resume'))
    enters[exact & ~reached_by_cfi] = -1
    enters[m & cut_by_trap] = -1
    is_entry = enters >= 0
    ent_pos = np.flatnonzero(is_entry)                # block indices that begin a handler
    ent_op = np.array([tab[e] for e in enters[ent_pos]])

    # handler execution k spans blocks ent_pos[k] .. ent_pos[k+1]-1; predecessor = ent_op[k-1],
    # successor = ent_op[k+1]
    sel = np.flatnonzero((ent_op[1:-1] == a.t_op) & (ent_op[:-2] == a.f_op)) + 1
    print(f'{a.t_op} entered from {a.f_op}: {len(sel):,} executions in {n:,} block events')

    paths = defaultdict(list)     # (site, path tuple) -> list of latency vectors
    for k in sel:
        b0, b1 = ent_pos[k], ent_pos[k + 1]
        if b1 - b0 > a.max_blocks:
            continue
        if any(kd in ('sync', 'trap', 'resume') for kd in kind[b0:b1 + 1]):
            continue
        site = ent_op[k + 1]
        path = tuple(zip(start[b0:b1], end[b0:b1], kind[b0:b1]))
        paths[(site, path)].append(lat[b0:b1])

    total = sum(len(v) for v in paths.values())
    rows = sorted(paths.items(), key=lambda kv: -len(kv[1]))
    for (site, path), lats in rows:
        share = len(lats) / total
        if share < a.min_share:
            continue
        L = np.array(lats)
        print(f'\n== site: {a.t_op} then {site}   n={len(lats):,} ({100*share:.1f}% of executions)'
              f'   span mean {L.sum(axis=1).mean():.2f}')
        print(f"   {'block':24s} {'ends by':8s} {'mean':>6s} {'p50':>4s} {'p90':>4s}  modes")
        for j, (s, e, kd) in enumerate(path):
            col = L[:, j]
            vc = pd.Series(col).value_counts(normalize=True).sort_index()
            modes = ' '.join(f'{int(c)}c:{100*v:.0f}%' for c, v in vc[vc >= 0.05].items())
            tag = f'{s:#x}-{e:#x}' if e >= 0 else f'{s:#x}-'
            mark = '  <- entry' if j == 0 else ''
            print(f"   {tag:24s} {kd:8s} {col.mean():6.2f} {int(np.median(col)):4d} "
                  f"{int(np.percentile(col, 90)):4d}  {modes}{mark}")


if __name__ == '__main__':
    main()
