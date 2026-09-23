#!/usr/bin/env python3
"""Pick fused-dispatch guards from measured dispatch profiles (step 2 of the loop).

Takes one or more `dispatch_stats` captures of the BASELINE build and emits the guard list
for the next variant, plus a per-benchmark prediction that step 4 checks against.

  lua_select_fusion.py --optab configs/lua/lua_optab_fusebase.json \
      --bench mandelbrot=trace.lua-fusebase-mandelbrot.dispatch_stats.csv:6.542 \
      --bench sieve=trace.lua-fusebase-sieve.dispatch_stats.csv:4.607 \
      --max-guards 8 --out ../lua-dispatch/fuse/edges.v1.json

Ranking metric is recoverable excess, n*(mean - floor), where floor is the cheapest observed
arrival at that handler in the same capture. Gates come from the Act-2 postmortem
(software/lua-dispatch/reports/dispatch-fused.md):
  * skip a handler whose modal successor already arrives cheaply (nothing to win)
  * skip a monomorphic handler (the BTB already predicts it; the guard is pure cost)
  * require the summed excess to beat the guard's measured miss cost on every capture
"""
import argparse
import datetime
import json
import sys
from pathlib import Path

import pandas as pd

MIN_GAIN = 5.0        # cyc: mean - floor on the guarded edge
# NO share-based gate. A pair can be 100% of its source handler's transitions and still be
# mispredicted on every arrival, because share is a software-level property while
# prediction happens at a machine-level dispatch site. spectralnorm's CALL -> ADD is 100%
# of CALL's transitions, costs 19 cycles against a floor of 3, and a >95% rule discarded
# 4.72% of that benchmark's runtime. p50 - floor already measures what such a rule guesses.

# Handlers that leave through the interpreter loop head (`goto startfunc` / `goto
# returning` in lvm.c) rather than through their own tail dispatch. Their transitions are
# all served by ONE machine site, so they compete for a single guard -- the ENTRY guard.
ENTRY_SOURCES = {'CALL', 'TAILCALL', 'RETURN', 'RETURN0', 'RETURN1'}
ENTRY_SITE = 'ENTRY'

MIN_EXCESS_FRAC = 0.002   # 0.2% of the summed window
MISS_COST = 1.0       # cyc per non-firing guard evaluation (measured: <= 1)
MIN_N = 10000


def load(csv, optab):
    d = pd.read_csv(csv, skipinitialspace=True)
    for c in ('from_handler', 'to_handler'):
        d[c] = d[c].str.strip()
    d['f'] = d['from_handler'].map(optab); d['t'] = d['to_handler'].map(optab)
    unmapped = d['count'][d['f'].isna() | d['t'].isna()].sum()
    d = d.dropna(subset=['f', 't']).copy()
    d['sum'] = d['count'] * d['mean']
    g = d.groupby(['f', 't'], as_index=False).agg(n=('count', 'sum'), sum=('sum', 'sum'),
                                                 mn=('min', 'min'), p50=('p50', 'median'))
    g['mean'] = g['sum'] / g['n']
    g['from_n'] = g['f'].map(g.groupby('f')['n'].sum())
    g['share'] = g['n'] / g['from_n']
    return g, unmapped


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--optab', required=True)
    ap.add_argument('--bench', action='append', required=True,
                    metavar='NAME=CSV:WINDOW_SECONDS')
    ap.add_argument('--max-guards', type=int, default=8)
    ap.add_argument('--out')
    a = ap.parse_args()
    optab = json.load(open(a.optab))

    profiles, tables = {}, {}
    raw = {}
    for spec in a.bench:
        name, rest = spec.split('=', 1)
        csv, win = rest.rsplit(':', 1)
        g, unmapped = load(csv, optab)
        win = float(win) * 1e9
        raw[name] = (g, win, csv, unmapped)

    # Floor per target handler, POOLED over every capture: what that handler's entry block
    # costs when the dispatch into it was predicted. A workload that never predicts a given
    # handler has no cheap arrival of its own, so a per-capture floor would read its whole
    # cost as intrinsic (mandelbrot's MOVE: local floor 21, pooled floor 3).
    allp = pd.concat([g for g, _, _, _ in raw.values()])
    pooled_floor = allp[allp['n'] >= MIN_N].groupby('t')['p50'].min()

    for name, (g, win, csv, unmapped) in raw.items():
        g = g.copy()
        g['floor'] = g['t'].map(pooled_floor)
        g = g.dropna(subset=['floor'])
        g['excess'] = (g['n'] * (g['mean'] - g['floor'])).clip(lower=0)
        tables[name] = g
        profiles[name] = dict(csv=csv, window_cyc=win, dispatches=int(g['n'].sum()),
                              entry_cyc=float(g['sum'].sum()), excess_cyc=float(g['excess'].sum()),
                              unmapped_events=int(unmapped))
        if unmapped:
            print(f'WARNING {name}: {unmapped:,} events at unknown handler addresses '
                  f'(stale optab?)', file=sys.stderr)

    print('=' * 104)
    print('BASELINE PROFILE  (gate: fusion only pays where dispatch excess is a real share of the window)')
    print('=' * 104)
    print(f"{'bench':14s} {'window Gcyc':>11s} {'dispatches':>12s} {'entry %win':>10s} "
          f"{'excess Gcyc':>11s} {'excess %win':>11s} {'verdict':>10s}")
    for n, p in profiles.items():
        frac = 100 * p['excess_cyc'] / p['window_cyc']
        print(f"{n:14s} {p['window_cyc']/1e9:11.3f} {p['dispatches']:12,d} "
              f"{100*p['entry_cyc']/p['window_cyc']:9.1f}% {p['excess_cyc']/1e9:11.3f} {frac:10.1f}% "
              f"{'target' if frac >= 15 else 'control':>10s}")

    # aggregate candidates across captures
    tot_win = sum(p['window_cyc'] for p in profiles.values())
    cand = {}
    for name, g in tables.items():
        for r in g.itertuples():
            if r.n < MIN_N:
                continue
            c = cand.setdefault((r.f, r.t), dict(excess=0.0, per={}, miss=0.0,
                                                site=ENTRY_SITE if r.f in ENTRY_SOURCES else r.f))
            c['excess'] += r.excess
            c['per'][name] = dict(n=int(r.n), share=round(float(r.share), 4),
                                  mean=round(float(r.mean), 2), floor=float(r.floor),
                                  excess_Mcyc=round(r.excess / 1e6, 1))
    # Miss traffic = everything that flows through the SAME MACHINE SITE and is not the
    # guarded target, so it pays the compare and falls through. For a handler tail that is
    # the handler's other exits; for ENTRY it is every frame transition (all CALL/RETURN*
    # sources together), which is why it must be summed per site, not per source handler.
    site_traffic = {}
    for g in tables.values():
        for r in g.itertuples():
            site = ENTRY_SITE if r.f in ENTRY_SOURCES else r.f
            site_traffic[site] = site_traffic.get(site, 0.0) + float(r.n)
    for (f, t), c in cand.items():
        matched = sum(float(g[(g['f'] == f) & (g['t'] == t)]['n'].sum()) for g in tables.values())
        c['miss'] = max(site_traffic.get(c['site'], 0.0) - matched, 0.0)

    def gated(ft, c):
        f, t = ft
        why = []
        gains = [p['mean'] - p['floor'] for p in c['per'].values()]
        if max(gains) < MIN_GAIN:
            why.append(f'arrival already cheap (max mean-floor {max(gains):.1f} < {MIN_GAIN})')
        if c['excess'] < MIN_EXCESS_FRAC * tot_win:
            why.append(f'excess {c["excess"]/1e6:.1f}M below {100*MIN_EXCESS_FRAC:.1f}% of summed window')
        if c['excess'] <= MISS_COST * c['miss']:
            why.append(f'excess {c["excess"]/1e6:.1f}M <= miss cost {MISS_COST*c["miss"]/1e6:.1f}M')
        return why

    print('\n' + '=' * 104)
    print('CANDIDATE EDGES (summed excess across captures; one guard per handler)')
    print('=' * 104)
    print(f"{'edge':26s} {'excess Mcyc':>11s} {'miss traffic':>12s} {'per-bench share':>34s}  status")
    rows = sorted(cand.items(), key=lambda kv: -kv[1]['excess'])
    chosen, seen_from = [], set()
    for ft, c in rows[:40]:
        why = gated(ft, c)
        shares = ' '.join(f'{b[:4]}:{p["share"]*100:.0f}%/{p["mean"]:.0f}c' for b, p in c['per'].items())
        site_tag = '' if c['site'] != ENTRY_SITE else ' [ENTRY]'
        if why:
            status = 'skip: ' + why[0]
        elif c['site'] in seen_from:
            status = f"skip: site {c['site']} already guarded"
        elif len(chosen) >= a.max_guards:
            status = 'skip: over --max-guards'
        else:
            status = 'SELECT'
            seen_from.add(c['site'])
            chosen.append((ft, c))
        print(f"{ft[0]+' -> '+ft[1]+site_tag:32s} {c['excess']/1e6:11.1f} {c['miss']/1e6:11.1f}M "
              f"{shares:>34s}  {status}")

    # placebo target: a handler that never follows this one in any capture (layout control)
    all_ops = sorted(set(optab.values()))
    guards = []
    for (f, t), c in chosen:
        succ = set()
        for g in tables.values():
            succ |= set(g[g['f'] == f]['t'])
        cold = [o for o in all_ops if o not in succ and o != t]
        guards.append(dict(**{'from': f, 'to': t}, site=c['site'],
                           placebo_to=cold[0] if cold else t,
                           excess_Mcyc=round(c['excess'] / 1e6, 1), per_bench=c['per']))

    # prediction per benchmark, for step 4 to check
    pred = {}
    for name, g in tables.items():
        sel = g[[(r.f, r.t) in {(x['from'], x['to']) for x in guards} for r in g.itertuples()]]
        peel = g[[(r.f in {x['from'] for x in guards}) and
                  (r.f, r.t) not in {(x['from'], x['to']) for x in guards} for r in g.itertuples()]]
        pred[name] = dict(window_s=profiles[name]['window_cyc'] / 1e9,
                          hit_n=int(sel['n'].sum()),
                          hit_only_Mcyc=round(float(sel['excess'].sum()) / 1e6, 1),
                          peel_upper_Mcyc=round(float(peel['excess'].sum()) / 1e6, 1),
                          miss_n=int(peel['n'].sum()),
                          miss_cost_Mcyc=round(MISS_COST * float(peel['n'].sum()) / 1e6, 1))
        p = pred[name]
        p['predicted_speedup_pct_low'] = round(100 * (p['hit_only_Mcyc'] - p['miss_cost_Mcyc'])
                                               / (p['window_s'] * 1e3), 2)
        p['predicted_speedup_pct_high'] = round(100 * (p['hit_only_Mcyc'] + p['peel_upper_Mcyc']
                                                       - p['miss_cost_Mcyc']) / (p['window_s'] * 1e3), 2)

    print('\n' + '=' * 104)
    print('PREDICTION for the selected guard set (step 4 checks these)')
    print('=' * 104)
    print(f"{'bench':14s} {'hit n':>11s} {'hit-only':>9s} {'peel upper':>11s} {'miss n':>11s} "
          f"{'miss cost':>10s} {'predicted speedup':>19s}")
    for n, p in pred.items():
        print(f"{n:14s} {p['hit_n']:11,d} {p['hit_only_Mcyc']:8.1f}M {p['peel_upper_Mcyc']:10.1f}M "
              f"{p['miss_n']:11,d} {p['miss_cost_Mcyc']:9.1f}M "
              f"{p['predicted_speedup_pct_low']:8.2f}% .. {p['predicted_speedup_pct_high']:.2f}%")

    spec = dict(generated=datetime.datetime.now().isoformat(timespec='seconds'),
                optab=a.optab, profiles=profiles,
                gates=dict(min_gain_cyc=MIN_GAIN, min_excess_frac=MIN_EXCESS_FRAC,
                           miss_cost_cyc=MISS_COST, min_n=MIN_N,
                           floor='pooled min-of-p50 over all captures',
                           entry_sources=sorted(ENTRY_SOURCES),
                           note='no share-based gate; miss traffic counted per machine site'),
                guards=guards, loop_guard=None, prediction=pred)
    if a.out:
        Path(a.out).write_text(json.dumps(spec, indent=1) + '\n')
        print(f'\n{len(guards)} guards -> {a.out}')


if __name__ == '__main__':
    main()
