#!/usr/bin/env python3
"""Does ranking dispatch edges by whole-handler span pick the same guards as ranking by the
entry block?

On an unfused computed-goto interpreter every op boundary is a `jr`, so a jalr-stamped
tracer measures the whole-handler span exactly: span is the best signal such a tracer can
have, with no emulation needed. The entry block is the dispatch cost alone; span = entry +
handler body. The two rankings agree only where the body cost does not depend on the
predecessor (or varies little). Where they disagree, the span view is being driven by body
variance -- cache/data effects inside the handler -- that a guard cannot remove.

Both inputs are dispatch_stats CSVs of the SAME capture: one decoded with the default entry
unit, one with "span": "handler". Excess = n·(mean − floor), floor = min-of-p50 into that
handler over hot predecessors, computed on each unit separately (as the selection tool does).

  lua_span_vs_entry.py --optab configs/lua/lua_optab_fusebase.json \
      --entry bundles/<b>/out/lua.dispatch_stats.csv --span bundles/<b>/out-span/ref/lua.dispatch_stats.csv \
      --window 6.548791 --label mandelbrot
"""
import argparse
import json

import pandas as pd

MIN_N = 10_000


def load(csv, optab):
    d = pd.read_csv(csv, skipinitialspace=True)
    for c in ('from_handler', 'to_handler'):
        d[c] = d[c].astype(str).str.strip()
    d['f'] = d['from_handler'].map(optab); d['t'] = d['to_handler'].map(optab)
    d = d.dropna(subset=['f', 't']).copy()
    d['sum'] = d['count'] * d['mean']
    g = d.groupby(['f', 't']).agg(n=('count', 'sum'), sum=('sum', 'sum'), p50=('p50', 'median'),
                                 p90=('p90', 'median'))
    g['mu'] = g['sum'] / g['n']
    hot = g[g.n >= MIN_N]
    floor = hot.groupby('t')['p50'].min()
    g['floor'] = g.index.get_level_values('t').map(floor).to_numpy()
    g['excess'] = (g['n'] * (g['mu'] - g['floor'])).clip(lower=0)
    return g


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--optab', required=True)
    ap.add_argument('--entry', required=True)
    ap.add_argument('--span', required=True)
    ap.add_argument('--window', type=float, required=True)
    ap.add_argument('--label', default='')
    ap.add_argument('--top', type=int, default=12)
    a = ap.parse_args()
    optab = json.load(open(a.optab))
    win = a.window * 1e9
    E, S = load(a.entry, optab), load(a.span, optab)
    J = E.join(S, lsuffix='_e', rsuffix='_s', how='inner')
    J = J[J.n_e >= MIN_N].copy()
    J['body'] = J.mu_s - J.mu_e                       # handler body cost on this edge
    J['rank_e'] = J.excess_e.rank(ascending=False).astype(int)
    J['rank_s'] = J.excess_s.rank(ascending=False).astype(int)
    sp = float(J.excess_e.rank().corr(J.excess_s.rank()))
    tops = {k: len(set(J.excess_e.nlargest(k).index) & set(J.excess_s.nlargest(k).index)) for k in (3, 5, 10)}
    print('=' * 100)
    print(f"{a.label}: {len(J)} hot edges   entry-unit excess {J.excess_e.sum()/1e9:.3f} G ({100*J.excess_e.sum()/win:.1f}% of window)"
          f"   span-unit excess {J.excess_s.sum()/1e9:.3f} G ({100*J.excess_s.sum()/win:.1f}%)")
    print(f"  Spearman(entry vs span excess) {sp:.3f}; top-3/5/10 overlap {tops[3]}/3 {tops[5]}/5 {tops[10]}/10")
    # body variance across predecessors of the same target: how much of the span floor/excess is body
    print(f"\n  per target: spread of body cost across hot predecessors (span − entry), cycles")
    bt = J.groupby(level='t').agg(preds=('body', 'size'), body_min=('body', 'min'), body_max=('body', 'max'),
                                  n=('n_e', 'sum'))
    bt['spread'] = bt.body_max - bt.body_min
    for t, r in bt[bt.preds >= 2].sort_values('spread', ascending=False).head(8).iterrows():
        print(f"    {t:8s} {int(r.preds)} preds  body {r.body_min:5.1f} .. {r.body_max:5.1f}  spread {r.spread:5.1f}  ({r.n/1e6:.1f}M arrivals)")
    print(f"\n  {'edge':22s} {'n':>8s} | {'entry':>6s} {'floor':>5s} {'excess M':>9s} {'rank':>4s} | {'span':>6s} {'floor':>5s} {'excess M':>9s} {'rank':>4s} | {'body':>5s}  verdict")
    top = J[(J.rank_e <= a.top) | (J.rank_s <= a.top)].sort_values('rank_e')
    for (f, t), r in top.iterrows():
        if r.rank_e <= 3 and r.rank_s > 5:
            v = 'span BURIES a real dispatch edge'
        elif r.rank_s <= 3 and r.rank_e > 5:
            v = 'span PROMOTES a body-variance edge'
        elif abs(r.rank_e - r.rank_s) >= 3:
            v = 'moved'
        else:
            v = ''
        print(f"  {f + ' -> ' + t:22s} {r.n_e/1e6:7.1f}M | {r.mu_e:6.2f} {r.floor_e:5.0f} {r.excess_e/1e6:9.1f} {int(r.rank_e):4d} | "
              f"{r.mu_s:6.2f} {r.floor_s:5.0f} {r.excess_s/1e6:9.1f} {int(r.rank_s):4d} | {r.body:5.1f}  {v}")


if __name__ == '__main__':
    main()
