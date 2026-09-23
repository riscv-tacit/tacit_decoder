#!/usr/bin/env python3
"""Act-2 report for the Lua dispatch case study: profile-guided fused dispatch,
with the -fno-crossjumping build (`ncj`) as the baseline.

Inputs, all already in the decoder directory:
  * dispatch_stats CSVs  - handler-entry latency conditioned on the previous handler
  * bb_pair_stats CSVs   - per-BB totals; covers 99.7-100.2% of the traced window
  * dispatch_seq CSVs    - 40M-event handler streams (order-k predictability)
  * configs/lua/lua_optab_*.json - handler entry addr -> opcode, per build
Run from the tacit_decoder directory.
"""
import bisect
import json
import subprocess
import sys

import pandas as pd

SP = 'configs/lua'
LUA = '../lua-dispatch'
tab = lambda n: json.load(open(f'{SP}/{n}.json'))
NCJ = tab('lua_optab_ncj')

# luaV_execute bounds per build (nm -S); target clock 1 GHz => 1 s == 1 Gcyc
LV = {'ncj': (0x1ff46, 0x1ff46 + 0x3f38),
      'fused': (0x1ff46, 0x1ff46 + 0x400e),
      'fused3': (0x1ff46, 0x1ff46 + 0x3e76)}

# baseline (ncj) capture, variant capture, wall durations (s) from the trace-run uartlogs
CASE = {
 #  bench          base dispatch_stats                    base bb_pair                            s      variant  variant dispatch_stats                    variant bb_pair                          s
 'nbody':        ('trace.lua-ncj-nbody.dispatch_stats.csv',        'trace.lua-ncj-nbody.bb_pair_stats.csv',        3.966, 'fused',  'trace.lua-fused-nbody.dispatch_stats.csv',        'trace.lua-fused-nbody.bb_pair_stats.csv',        3.989),
 'fannkuch':     ('trace.lua-ncj-fannkuch.dispatch_stats.csv',     'trace.lua-ncj-fannkuch.bb_pair_stats.csv',     4.341, 'fused',  'trace.lua-fused-fannkuch.dispatch_stats.csv',     'trace.lua-fused-fannkuch.bb_pair_stats.csv',     4.103),
 'binarytrees':  ('trace.lua-ncj-binarytrees.dispatch_stats.csv',  'trace.lua-ncj-binarytrees.bb_pair_stats.csv',  3.622, 'fused',  'trace.lua-fused-binarytrees.dispatch_stats.csv',  'trace.lua-fused-binarytrees.bb_pair_stats.csv',  3.722),
 'sieve':        ('trace.lua-ncj-sieve.dispatch_stats.csv',        'trace.lua-ncj-sieve.bb_pair_stats.csv',        4.607, 'fused',  'trace.lua-fused-sieve.dispatch_stats.csv',        'trace.lua-fused-sieve.bb_pair_stats.csv',        4.781),
 'fasta':        ('trace.lua-micro-fasta.dispatch_stats.csv',        'trace.lua-micro-fasta.bb_pair_stats.csv',        3.743, 'fused3', 'trace.lua-fused3-fasta.dispatch_stats.csv',        'trace.lua-fused3-fasta.bb_pair_stats.csv',        3.641),
 'mandelbrot':   ('trace.lua-micro-mandelbrot.dispatch_stats.csv',   'trace.lua-micro-mandelbrot.bb_pair_stats.csv',   6.542, 'fused3', 'trace.lua-fused3-mandelbrot.dispatch_stats.csv',   'trace.lua-fused3-mandelbrot.bb_pair_stats.csv',   5.522),
 'queens':       ('trace.lua-micro-queens.dispatch_stats.csv',       'trace.lua-micro-queens.bb_pair_stats.csv',       2.013, 'fused3', 'trace.lua-fused3-queens.dispatch_stats.csv',       'trace.lua-fused3-queens.bb_pair_stats.csv',       1.995),
 'spectralnorm': ('trace.lua-micro-spectralnorm.dispatch_stats.csv', 'trace.lua-micro-spectralnorm.bb_pair_stats.csv', 7.076, 'fused3', 'trace.lua-fused3-spectralnorm.dispatch_stats.csv', 'trace.lua-fused3-spectralnorm.bb_pair_stats.csv', 6.297),
}
# guarded edges per source variant (parsed from lvm.c; see EDGES check below)
EDGES = {'fused':  [('GETTABLE','GETTABLE'), ('GETFIELD','GETFIELD'), ('SETTABLE','ADDI'), ('ADDI','LE')],
         'fused3': [('LOADI','FORPREP'), ('ADDI','GETTABLE'), ('ADD','MOVE'), ('MUL','MUL'),
                    ('LT','GETTABLE'), ('TEST','GETUPVAL')]}
LOOP_GUARD = {'fused': None, 'fused3': 'ADD'}
# order-k modal share of the handler stream, from dispatch_seq replay (40M events)
ORDK = {'nbody': (.617,.795,.858,.895), 'fannkuch': (.496,.875,.933,.940),
        'fasta': (.781,.945,.945,.973), 'mandelbrot': (.664,.868,.995,.995),
        'queens': (.769,.873,.882,.911), 'spectralnorm': (.706,.929,.978,.978)}


def dispatch(csv, optab=NCJ):
    """(from,to) handler-entry latency, plus per-target floor and recoverable excess."""
    d = pd.read_csv(csv, skipinitialspace=True)
    for c in ('from_handler', 'to_handler'):
        d[c] = d[c].str.strip()
    d['f'] = d['from_handler'].map(optab); d['t'] = d['to_handler'].map(optab)
    d = d.dropna(subset=['f', 't']).copy()
    d['sum'] = d['count'] * d['mean']
    g = d.groupby(['f', 't'], as_index=False).agg(n=('count', 'sum'), sum=('sum', 'sum'),
                                                  mn=('min', 'min'), p50=('p50', 'median'))
    g['mean'] = g['sum'] / g['n']
    g = g.merge(g.groupby('t')['mn'].min().rename('floor'), on='t')
    g['excess'] = g['n'] * (g['mean'] - g['floor'])
    g = g.sort_values(['f', 'n'], ascending=[True, False])
    g['rank'] = g.groupby('f').cumcount()
    return g


def bbtot(csv):
    d = pd.read_csv(csv, skipinitialspace=True)
    d['start'] = d['bb'].str.strip().str.split('-').str[0].apply(lambda s: int(s, 16))
    d['cyc'] = d['count'] * d['mean']
    return d.groupby('start', as_index=False).agg(cyc=('cyc', 'sum'), n=('count', 'sum'))


def symbols(build):
    out = subprocess.run(['nm', '-S', '--numeric-sort', '--defined-only',
                          f'{LUA}/lua-riscv-{build}/src/lua' if build != 'ncj' else f'{LUA}/lua-riscv-ncj/src/lua'],
                         capture_output=True, text=True).stdout
    a = []
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 3 and p[-2] in 'tTwW':
            try: a.append((int(p[0], 16), p[-1]))
            except ValueError: pass
    a = sorted(set(a))
    return [x[0] for x in a], [x[1] for x in a]


def sec(title):
    print('\n' + '=' * 118); print(title); print('=' * 118)


sec('1. BASELINE (-fno-crossjumping): what dispatch still costs')
print(f"{'bench':14s} {'window Gcyc':>11s} {'dispatches':>12s} {'cyc/disp':>8s} {'entry cyc':>9s} "
      f"{'entry %win':>10s} {'excess Gcyc':>11s} {'excess %win':>11s} {'modal share':>11s}")
B = {}
for b, (c0, p0, t0, var, c1, p1, t1) in CASE.items():
    g = dispatch(c0); win = t0 * 1e9
    B[b] = (g, win, var, t1)
    n, cyc, ex = g['n'].sum(), g['sum'].sum(), g['excess'].sum()
    modal = g[g['rank'] == 0]['n'].sum() / n
    print(f"{b:14s} {win/1e9:11.3f} {n:12,d} {win/n:8.1f} {cyc/n:9.2f} {100*cyc/win:9.1f}% "
          f"{ex/1e9:11.3f} {100*ex/win:10.1f}% {100*modal:10.1f}%")
print("\nexcess = sum over edges of n*(mean - floor), floor = cheapest observed arrival at that handler.")

sec('2. HOW MUCH OF THE EXCESS ONE GUARD PER HANDLER CAN REACH')
print(f"{'bench':14s} {'top1':>7s} {'top2':>7s} {'top3':>7s} {'miss traffic':>13s} {'break-even cyc/miss':>20s}")
for b, (g, win, var, t1) in B.items():
    ex = g['excess'].sum()
    cap = [g[g['rank'] < k]['excess'].sum() for k in (1, 2, 3)]
    miss = g[g['rank'] >= 1]['n'].sum()
    print(f"{b:14s} {100*cap[0]/ex:6.1f}% {100*cap[1]/ex:6.1f}% {100*cap[2]/ex:6.1f}% "
          f"{miss/1e6:12.1f}M {cap[0]/miss:19.2f}")

sec('3. THE SHIPPED EDGE SETS vs EACH BENCHMARK\'S OWN OPPORTUNITY')
for var, edges in EDGES.items():
    print(f"\n--- {var}: {len(edges)} guards" + (f" + loop-head guard on {LOOP_GUARD[var]}" if LOOP_GUARD[var] else ""))
    hdr = f"    {'guard':26s}" + ''.join(f"{b[:11]:>12s}" for b in CASE)
    print(hdr); print(f"    {'':26s}" + ''.join(f"{'rank/%win':>12s}" for _ in CASE))
    for e in edges:
        row = f"    {e[0]+' -> '+e[1]:26s}"
        for b, (g, win, _, _) in B.items():
            m = g[(g['f'] == e[0]) & (g['t'] == e[1])]
            if len(m) == 0 or m['n'].iloc[0] < 1000:
                row += f"{'-':>12s}"; continue
            r = m.iloc[0]
            rank = (g['excess'] > r['excess']).sum() + 1
            row += f"{f'#{rank}/{100*r.excess/win:.1f}%':>12s}"
        print(row)
print("\nrank = position of that edge in the benchmark's excess ranking; %win = excess as share of window.")

sec('4. MEASURED, END TO END (bb_pair_stats covers 99.7-100.2% of the window)')
print(f"{'bench':14s} {'variant':7s} {'base s':>7s} {'fused s':>8s} {'speedup':>8s} | "
      f"{'luaV base':>10s} {'luaV var':>9s} {'d luaV':>8s} | {'outside base':>12s} {'d outside':>10s} | "
      f"{'BB execs':>9s} {'d execs':>8s} {'cyc/exec':>9s}")
for b, (c0, p0, t0, var, c1, p1, t1) in CASE.items():
    g0, g1 = bbtot(p0), bbtot(p1)
    lo0, hi0 = LV['ncj']; lo1, hi1 = LV[var]
    l0 = g0[(g0.start >= lo0) & (g0.start < hi0)]; l1 = g1[(g1.start >= lo1) & (g1.start < hi1)]
    o0 = g0['cyc'].sum() - l0['cyc'].sum(); o1 = g1['cyc'].sum() - l1['cyc'].sum()
    print(f"{b:14s} {var:7s} {t0:7.3f} {t1:8.3f} {100*(t0-t1)/t0:+7.1f}% | "
          f"{l0['cyc'].sum()/1e9:9.3f}G {l1['cyc'].sum()/1e9:8.3f}G {(l1['cyc'].sum()-l0['cyc'].sum())/1e6:+7.0f}M | "
          f"{o0/1e9:11.3f}G {(o1-o0)/1e6:+9.0f}M | {l0['n'].sum()/1e6:8.1f}M "
          f"{(l1['n'].sum()-l0['n'].sum())/1e6:+7.1f}M {l0['cyc'].sum()/l0['n'].sum():5.2f}->{l1['cyc'].sum()/l1['n'].sum():.2f}")

sec('5. PER-EDGE EFFECT, and the instrument gap')
for b, (c0, p0, t0, var, c1, p1, t1) in CASE.items():
    a = dispatch(c0); c = dispatch(c1, tab(f'lua_optab_{var}'))
    lost = a['n'].sum() - c['n'].sum()
    m = a.merge(c, on=['f', 't'], how='left', suffixes=('_0', '_1'))
    edges = set(EDGES[var]); guarded = {f for f, _ in EDGES[var]}
    hit = m[[(r.f, r.t) in edges for r in m.itertuples()]]
    peel = m[[(r.f in guarded and (r.f, r.t) not in edges) for r in m.itertuples()]]
    print(f"\n--- {b} ({var}): {100*(t0-t1)/t0:+.1f}%, dispatch events lost from the instrument: {lost:,d} "
          f"({100*lost/a['n'].sum():.1f}%)")
    if len(hit):
        print(f"    {'guarded edge':26s} {'n':>11s} {'share':>6s} {'base mean':>9s} {'variant mean':>12s} {'status':>9s}")
        fn = a.groupby('f')['n'].sum()
        for r in hit.itertuples():
            st = 'invisible' if pd.isna(r.mean_1) else 'measured'
            mv = 'n/a' if pd.isna(r.mean_1) else f'{r.mean_1:.2f}'
            print(f"    {r.f+' -> '+r.t:26s} {int(r.n_0):11,d} {100*r.n_0/fn[r.f]:5.1f}% {r.mean_0:9.2f} {mv:>12s} {st:>9s}")
    pk = peel.dropna(subset=['mean_1']).nlargest(4, 'n_0')
    if len(pk):
        print(f"    peeled (same handler, non-guarded target):")
        for r in pk.itertuples():
            print(f"    {r.f+' -> '+r.t:26s} {int(r.n_0):11,d} {'':6s} {r.mean_0:9.2f} {r.mean_1:12.2f} "
                  f"{r.n_0*(r.mean_1-r.mean_0)/1e6:+7.1f}M")

sec('6. CEILING BY HISTORY DEPTH (dispatch_seq replay; M fitted per benchmark)')
print(f"{'bench':14s} {'M cyc':>6s} {'o1':>6s} {'o2':>6s} {'o3':>6s} {'o4':>6s} | "
      f"{'excess@o1':>10s} {'@o2':>8s} {'@o3':>8s} | {'o1->o2':>8s} {'o1->o3':>8s} {'o1->o4':>8s}")
for b, ok in ORDK.items():
    g, win, var, t1 = B[b]
    n, ex = g['n'].sum(), g['excess'].sum()
    M = ex / (n * (1 - ok[0]))
    e = [n * (1 - o) * M for o in ok]
    print(f"{b:14s} {M:6.1f} {100*ok[0]:5.1f}% {100*ok[1]:5.1f}% {100*ok[2]:5.1f}% {100*ok[3]:5.1f}% | "
          f"{e[0]/1e9:9.3f}G {e[1]/1e9:7.3f}G {e[2]/1e9:7.3f}G | {100*(e[0]-e[1])/win:7.1f}% "
          f"{100*(e[0]-e[2])/win:7.1f}% {100*(e[0]-e[3])/win:7.1f}%")
print("\nM = implied cost of one unpredicted dispatch = excess / (dispatches * (1 - order-1 share)).")
print("o1->ok columns: window share recovered by lifting prediction from order-1 to order-k.")

sec('7. CONFOUNDS: per-function cycle movement outside the interpreter')
for b in ('nbody', 'binarytrees', 'spectralnorm'):
    c0, p0, t0, var, c1, p1, t1 = CASE[b]
    a0, n0 = symbols('ncj'); a1, n1 = symbols(var)
    def byfn(g, addrs, names):
        g = g[g.start < 0xffffffff00000000]
        idx = [bisect.bisect_right(addrs, s) - 1 for s in g['start']]
        return g.assign(fn=[names[i] if i >= 0 else '?' for i in idx]).groupby('fn').agg(
            cyc=('cyc', 'sum'), n=('n', 'sum'))
    f0, f1 = byfn(bbtot(p0), a0, n0), byfn(bbtot(p1), a1, n1)
    m = pd.concat([f0['cyc'].rename('base'), f1['cyc'].rename('var'),
                   f0['n'].rename('nb'), f1['n'].rename('nv')], axis=1).fillna(0)
    m['d'] = m['var'] - m['base']; m['dn'] = m['nv'] - m['nb']
    m = m.reindex(m['d'].abs().sort_values(ascending=False).index).head(6)
    print(f"\n--- {b} ({var})")
    print(f"    {'function':26s} {'base Mcyc':>10s} {'var Mcyc':>9s} {'delta':>8s} {'d BB execs':>11s}")
    for fn, r in m.iterrows():
        print(f"    {fn:26s} {r['base']/1e6:10.1f} {r['var']/1e6:9.1f} {r['d']/1e6:+8.1f} {r['dn']/1e6:+10.2f}M")
print("\nA delta with ~zero BB-execution change is front-end collateral (layout/i-cache), not extra work;")
print("a large BB-execution change with a matching opposite delta elsewhere is an inlining shift.")
