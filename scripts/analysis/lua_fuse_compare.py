#!/usr/bin/env python3
"""Step 4: compare a fused variant against the baseline, and against its own prediction.

Uses the instruments in the order the Act-2 postmortem trusts them:
  1. guest window (trace-run duration)          -- ground truth
  2. bb_pair_stats totals, split luaV / outside -- covers ~100% of the window
  3. dispatch_stats per edge                    -- ONLY where the event-count canary passes
     (a fused arrival into a cloned handler entry is invisible to the handler-keyed
      instrument, and it also corrupts the next edge's `from` attribution)

  lua_fuse_compare.py --base base --var v1 --edges ../lua-dispatch/fuse/edges.v1.json
Run from the tacit_decoder directory.
"""
import argparse
import json
from pathlib import Path

import pandas as pd

LUA = Path('/scratch/iansseijelly/tacit-chipyard/software/lua-dispatch')


def variant(tag):
    man = json.loads((LUA / f'lua-fuse-{tag}/manifest.json').read_text())
    lv = man['luaV_execute']
    lo = int(lv['addr'], 16)
    return man, (lo, lo + lv['bytes'])


def bb(path):
    d = pd.read_csv(path, skipinitialspace=True)
    d['start'] = d['bb'].str.strip().str.split('-').str[0].apply(lambda s: int(s, 16))
    d['cyc'] = d['count'] * d['mean']
    return d.groupby('start', as_index=False).agg(cyc=('cyc', 'sum'), n=('count', 'sum'))


def disp(path, optab):
    d = pd.read_csv(path, skipinitialspace=True)
    for c in ('from_handler', 'to_handler'):
        d[c] = d[c].str.strip()
    d['f'] = d['from_handler'].map(optab); d['t'] = d['to_handler'].map(optab)
    d = d.dropna(subset=['f', 't']).copy()
    d['sum'] = d['count'] * d['mean']
    g = d.groupby(['f', 't'], as_index=False).agg(n=('count', 'sum'), sum=('sum', 'sum'))
    g['mean'] = g['sum'] / g['n']
    return g


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--base', required=True)
    ap.add_argument('--var', required=True)
    ap.add_argument('--edges', required=True)
    ap.add_argument('--prefix', default='trace.lua-fuse')
    a = ap.parse_args()

    bman, brange = variant(a.base)
    vman, vrange = variant(a.var)
    spec = json.loads(Path(a.edges).read_text())
    guards = {(g['from'], g['to']) for g in spec['guards']}
    guarded = {g['from'] for g in spec['guards']}
    pred = spec.get('prediction', {})
    bm = json.loads(Path(f'configs/lua/lua_fuse_{a.base}_manifest.json').read_text())
    vm = json.loads(Path(f'configs/lua/lua_fuse_{a.var}_manifest.json').read_text())
    bo = json.load(open(f'configs/lua/lua_optab_fuse{a.base}.json'))
    vo = json.load(open(f'configs/lua/lua_optab_fuse{a.var}.json'))

    print('=' * 112)
    print(f'VARIANT {a.var} vs BASELINE {a.base}    guards: '
          + ', '.join(f'{f}->{t}' for f, t in sorted(guards)) + (' [PLACEBO]' if vman['placebo'] else ''))
    print(f"luaV_execute: {bman['luaV_execute']['bytes']} B -> {vman['luaV_execute']['bytes']} B "
          f"({vman['luaV_execute']['bytes']-bman['luaV_execute']['bytes']:+d} B), "
          f"jr sites {bman['jr_sites']} -> {vman['jr_sites']}")
    print('=' * 112)

    print('\n1. INVARIANTS (a variant that changes these is not a valid comparison)')
    print(f"   {'bench':14s} {'guest output':>12s} {'child exit':>10s} {'dispatch events':>26s}")
    ok = {}
    for b in bm['jobs']:
        if b not in vm['jobs']:
            continue
        same_out = bm['jobs'][b]['guest_output'] == vm['jobs'][b]['guest_output']
        db = disp(f'{a.prefix}-{a.base}-{b}.dispatch_stats.csv', bo)['n'].sum()
        dv = disp(f'{a.prefix}-{a.var}-{b}.dispatch_stats.csv', vo)['n'].sum()
        lost = db - dv
        ok[b] = dict(same_out=same_out, lost=int(lost))
        print(f"   {b:14s} {'MATCH' if same_out else 'DIFFER!!':>12s} "
              f"{vm['jobs'][b]['child_exit']:10d} "
              f"{db:12,d} -> {dv:12,d}" + ('' if lost == 0 else f'  ({-lost:+,d}: instrument blind)'))

    print('\n2. MEASURED (window = ground truth; luaV/outside from bb_pair_stats)')
    print(f"   {'bench':14s} {'base s':>8s} {'var s':>8s} {'speedup':>8s} | {'d luaV':>8s} "
          f"{'d outside':>10s} {'d BB execs':>11s} | {'predicted':>16s} {'verdict':>9s}")
    for b in ok:
        wb, wv = bm['jobs'][b]['window_s'], vm['jobs'][b]['window_s']
        gb, gv = bb(f'{a.prefix}-{a.base}-{b}.bb_pair_stats.csv'), bb(f'{a.prefix}-{a.var}-{b}.bb_pair_stats.csv')
        lb = gb[(gb.start >= brange[0]) & (gb.start < brange[1])]
        lv = gv[(gv.start >= vrange[0]) & (gv.start < vrange[1])]
        dlua = lv['cyc'].sum() - lb['cyc'].sum()
        dout = (gv['cyc'].sum() - lv['cyc'].sum()) - (gb['cyc'].sum() - lb['cyc'].sum())
        dexec = lv['n'].sum() - lb['n'].sum()
        sp = 100 * (wb - wv) / wb
        p = pred.get(b)
        ps = f"{p['predicted_speedup_pct_low']:.1f}..{p['predicted_speedup_pct_high']:.1f}%" if p else '-'
        verdict = '-'
        if p:
            verdict = ('in range' if p['predicted_speedup_pct_low'] - 1 <= sp <= p['predicted_speedup_pct_high'] + 1
                       else 'OUT')
        print(f"   {b:14s} {wb:8.3f} {wv:8.3f} {sp:+7.1f}% | {dlua/1e6:+7.0f}M {dout/1e6:+9.0f}M "
              f"{dexec/1e6:+10.1f}M | {ps:>16s} {verdict:>9s}")

    print('\n3. PER-GUARD EFFECT (only benches whose canary passed in section 1)')
    for b in ok:
        if ok[b]['lost'] != 0:
            print(f"   {b}: skipped, {ok[b]['lost']:,} events invisible to the handler-keyed instrument")
            continue
        db = disp(f'{a.prefix}-{a.base}-{b}.dispatch_stats.csv', bo)
        dv = disp(f'{a.prefix}-{a.var}-{b}.dispatch_stats.csv', vo)
        m = db.merge(dv, on=['f', 't'], how='outer', suffixes=('_0', '_1'))
        hit = m[[(r.f, r.t) in guards for r in m.itertuples()]]
        peel = m[[(r.f in guarded and (r.f, r.t) not in guards) for r in m.itertuples()]]
        print(f"   --- {b}")
        for label, sub in (('guarded', hit), ('peeled', peel)):
            sub = sub.dropna(subset=['n_0']).nlargest(5, 'n_0')
            for r in sub.itertuples():
                if r.n_0 < 10000:
                    continue
                d = (r.mean_1 - r.mean_0) if pd.notna(r.mean_1) else float('nan')
                print(f"       {label:8s} {r.f+' -> '+r.t:24s} n={int(r.n_0):>11,d} "
                      f"{r.mean_0:6.2f} -> {r.mean_1 if pd.notna(r.mean_1) else float('nan'):6.2f} cyc "
                      f"({d:+6.2f})  {r.n_0*d/1e6:+8.1f}M")


if __name__ == '__main__':
    main()
