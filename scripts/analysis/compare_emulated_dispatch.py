#!/usr/bin/env python3
"""Reference clock vs emulated sparse clock, for the interpreter-dispatch profile.

Both CSVs come from the SAME decode of the SAME trace: the reference receivers ran on
tacit's per-event timestamps, the emulated ones on the timestamps a sparser format (e.g.
TNT + CYC, flushed every N branches or at every uninferable jump) would have attributed to
the same events. Instance counts are therefore identical by construction and only the
latencies differ. Three questions, in the order the fusion loop needs them answered:

  1. per edge (from-handler -> to-handler): does the emulated entry-block latency track
     the reference one? mean / p50 / p90, and the share of arrivals that look like a
     mispredict (>= --miss-cyc), which is the bimodal 3-vs-19 signature.
  2. per target handler: is the ORDER of predecessors by mean latency preserved, and does
     the emulated clock still name the same worst predecessor?
  3. across edges: is the guard-selection ranking, excess = n*(mean - floor) with the
     floor as min-of-p50 over hot predecessors (fuse-baseline.md s.2), preserved? Spearman
     over hot edges, top-k overlap, and total excess as a share of the window.

  compare_emulated_dispatch.py --optab configs/lua/lua_optab_fusebase.json \
      --ref  bundles/<b>/out/lua.dispatch_stats.csv          --ref-hist  .../lua.dispatch_hist.csv \
      --emu  bundles/<b>/out-emu-tnt6/lua.dispatch_stats.csv --emu-hist  .../lua.dispatch_hist.csv \
      --window 6.548791 --label "TNT+CYC, n=6" --out out/emu.base

Optionally, the same for plain basic blocks (bb_stats + bb_hist), for blocks that are not
handler entries (e.g. the guarded entry copy, or an upstream block that moved):
      --bb-ref .../lua.bb_stats.csv --bb-emu .../lua.bb_stats.csv \
      --bb-ref-hist .../lua.bb_hist.csv --bb-emu-hist .../lua.bb_hist.csv --blocks 0x1ffcc,0x2003c
"""
import argparse
import json
import sys
from pathlib import Path

import pandas as pd

MIN_N = 10_000


def load_stats(csv, optab):
    d = pd.read_csv(csv, skipinitialspace=True)
    for c in ('from_handler', 'to_handler'):
        d[c] = d[c].astype(str).str.strip()
    d['f'] = d['from_handler'].map(optab)
    d['t'] = d['to_handler'].map(optab)
    d = d.dropna(subset=['f', 't']).copy()
    d['sum'] = d['count'] * d['mean']
    g = d.groupby(['f', 't'], as_index=False).agg(
        n=('count', 'sum'), sum=('sum', 'sum'), mn=('min', 'min'),
        p50=('p50', 'median'), p90=('p90', 'median'), p99=('p99', 'median'))
    g['mean'] = g['sum'] / g['n']
    return g


def load_hist(csv, optab):
    if csv is None:
        return None
    d = pd.read_csv(csv, skipinitialspace=True)
    for c in ('from_handler', 'to_handler'):
        d[c] = d[c].astype(str).str.strip()
    d['f'] = d['from_handler'].map(optab)
    d['t'] = d['to_handler'].map(optab)
    return d.dropna(subset=['f', 't'])


def miss_share(hist, f, t, miss_cyc):
    if hist is None:
        return float('nan')
    h = hist[(hist.f == f) & (hist.t == t)]
    n = h['count'].sum()
    return float(h[h.cycles >= miss_cyc]['count'].sum() / n) if n else float('nan')


def modes(hist, f, t, k=2):
    """the k most populated integer latencies, with their mass share"""
    if hist is None:
        return ''
    h = hist[(hist.f == f) & (hist.t == t)].groupby('cycles')['count'].sum()
    n = h.sum()
    if not n:
        return ''
    top = h.sort_values(ascending=False).head(k)
    return ' '.join(f'{int(c)}c:{100*v/n:.0f}%' for c, v in top.items())


def excess_table(g):
    hot = g[g.n >= MIN_N]
    floor = hot.groupby('t')['p50'].min()
    g = g.copy()
    g['floor'] = g['t'].map(floor)
    g['excess'] = (g['n'] * (g['mean'] - g['floor'])).clip(lower=0)
    return g


def spearman(a, b):
    if len(a) < 3:
        return float('nan')
    return float(pd.Series(a).rank().corr(pd.Series(b).rank()))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--optab', required=True)
    ap.add_argument('--ref', required=True)
    ap.add_argument('--emu', required=True)
    ap.add_argument('--ref-hist')
    ap.add_argument('--emu-hist')
    ap.add_argument('--window', type=float, required=True, help='guest window, seconds at 1 GHz')
    ap.add_argument('--label', default='emulated')
    ap.add_argument('--miss-cyc', type=int, default=10,
                    help='an arrival at or above this many cycles counts as a mispredict-shaped one')
    ap.add_argument('--top-edges', type=int, default=25)
    ap.add_argument('--bb-ref'); ap.add_argument('--bb-emu')
    ap.add_argument('--bb-ref-hist'); ap.add_argument('--bb-emu-hist')
    ap.add_argument('--blocks', help='comma-separated block start addresses for the bb section')
    ap.add_argument('--out', required=True, help='prefix: writes <out>.txt and <out>.edges.csv')
    a = ap.parse_args()

    optab = json.load(open(a.optab))
    win = a.window * 1e9
    R, E = load_stats(a.ref, optab), load_stats(a.emu, optab)
    RH, EH = load_hist(a.ref_hist, optab), load_hist(a.emu_hist, optab)

    m = R.merge(E, on=['f', 't'], suffixes=('_ref', '_emu'))
    if (m.n_ref != m.n_emu).any():
        bad = m[m.n_ref != m.n_emu]
        print(f'WARNING: {len(bad)} edges differ in instance count between clocks '
              f'(should be impossible from one decode)', file=sys.stderr)
    m['n'] = m['n_ref']
    m['miss_ref'] = [miss_share(RH, f, t, a.miss_cyc) for f, t in zip(m.f, m.t)]
    m['miss_emu'] = [miss_share(EH, f, t, a.miss_cyc) for f, t in zip(m.f, m.t)]
    m['modes_ref'] = [modes(RH, f, t) for f, t in zip(m.f, m.t)]
    m['modes_emu'] = [modes(EH, f, t) for f, t in zip(m.f, m.t)]

    Rx, Ex = excess_table(R), excess_table(E)
    m = m.merge(Rx[['f', 't', 'floor', 'excess']].rename(columns={'floor': 'floor_ref', 'excess': 'excess_ref'}),
                on=['f', 't'], how='left')
    m = m.merge(Ex[['f', 't', 'floor', 'excess']].rename(columns={'floor': 'floor_emu', 'excess': 'excess_emu'}),
                on=['f', 't'], how='left')
    m = m.sort_values('n', ascending=False)
    m.to_csv(f'{a.out}.edges.csv', index=False)

    out = []
    P = out.append
    P('=' * 110)
    P(f'reference clock vs {a.label}   window {a.window:.3f} s   ({a.ref} vs {a.emu})')
    P('=' * 110)

    # ---- 1. per edge
    hot = m[m.n >= MIN_N].head(a.top_edges)
    P('')
    P(f'1. HOT EDGES  (top {len(hot)} by traffic; latency = target entry block; '
      f'miss% = share of arrivals >= {a.miss_cyc} cyc)')
    P(f"{'edge':22s} {'n':>12s} | {'mean':>6s} {'p50':>4s} {'p90':>4s} {'miss%':>6s} {'modes':>14s} | "
      f"{'mean':>6s} {'p50':>4s} {'p90':>4s} {'miss%':>6s} {'modes':>14s} | {'mean err':>9s}")
    P(f"{'':22s} {'':>12s} | {'--- reference ---':^40s} | {'--- ' + a.label + ' ---':^40s} |")
    for r in hot.itertuples():
        P(f"{r.f + ' -> ' + r.t:22s} {int(r.n):12,d} | {r.mean_ref:6.2f} {int(r.p50_ref):4d} {int(r.p90_ref):4d} "
          f"{100*r.miss_ref:5.1f}% {r.modes_ref:>14s} | {r.mean_emu:6.2f} {int(r.p50_emu):4d} {int(r.p90_emu):4d} "
          f"{100*r.miss_emu:5.1f}% {r.modes_emu:>14s} | {r.mean_emu - r.mean_ref:+9.2f}")
    allhot = m[m.n >= MIN_N]
    tot_ref = (allhot.n * allhot.mean_ref).sum()
    tot_emu = (allhot.n * allhot.mean_emu).sum()
    P(f"\n   summed entry-block cycles over hot edges: reference {tot_ref/1e9:.3f} G ({100*tot_ref/win:.1f}% of window), "
      f"{a.label} {tot_emu/1e9:.3f} G ({100*tot_emu/win:.1f}%)")
    P(f"   mean |mean error| over hot edges: {(allhot.mean_emu - allhot.mean_ref).abs().mean():.2f} cyc; "
      f"Spearman(mean) over hot edges: {spearman(allhot.mean_ref, allhot.mean_emu):.3f}")

    # ---- 2. per target: predecessor order
    P('')
    P('2. PREDECESSOR ORDER PER TARGET  (targets with >= 2 hot predecessors; '
      'worst = predecessor with the highest mean)')
    P(f"{'target':10s} {'#pred':>5s} {'spearman':>9s} {'worst ref':>12s} {'worst ' + a.label:>18s} "
      f"{'ref spread':>10s} {'emu spread':>10s}  same worst?")
    kept = 0
    for t, grp in allhot.groupby('t'):
        if len(grp) < 2:
            continue
        kept += 1
        wr = grp.loc[grp.mean_ref.idxmax()]
        we = grp.loc[grp.mean_emu.idxmax()]
        P(f"{t:10s} {len(grp):5d} {spearman(grp.mean_ref, grp.mean_emu):9.3f} "
          f"{wr.f + ' ' + f'{wr.mean_ref:.1f}c':>12s} {we.f + ' ' + f'{we.mean_emu:.1f}c':>18s} "
          f"{grp.mean_ref.max() - grp.mean_ref.min():10.2f} {grp.mean_emu.max() - grp.mean_emu.min():10.2f}  "
          f"{'yes' if wr.f == we.f else 'NO'}")
    if not kept:
        P('   (no target has two hot predecessors)')

    # ---- 3. ranking for guard selection
    P('')
    P('3. GUARD-SELECTION RANKING  excess = n*(mean - floor), floor = min p50 over hot predecessors, per clock')
    ex = allhot.dropna(subset=['excess_ref', 'excess_emu'])
    P(f"   total excess: reference {ex.excess_ref.sum()/1e9:.3f} G ({100*ex.excess_ref.sum()/win:.1f}% of window), "
      f"{a.label} {ex.excess_emu.sum()/1e9:.3f} G ({100*ex.excess_emu.sum()/win:.1f}%)")
    P(f"   Spearman(excess) over {len(ex)} hot edges: {spearman(ex.excess_ref, ex.excess_emu):.3f}")
    for k in (3, 5, 10):
        tr = set(ex.nlargest(k, 'excess_ref').apply(lambda r: (r.f, r.t), axis=1))
        te = set(ex.nlargest(k, 'excess_emu').apply(lambda r: (r.f, r.t), axis=1))
        P(f"   top-{k} overlap: {len(tr & te)}/{k}")
    P('')
    P(f"{'rank':>4s} {'reference edge':24s} {'excess M':>9s} {'floor':>5s} | {a.label + ' edge':24s} {'excess M':>9s} {'floor':>5s}")
    rr = ex.sort_values('excess_ref', ascending=False).head(10).reset_index()
    re_ = ex.sort_values('excess_emu', ascending=False).head(10).reset_index()
    for i in range(10):
        l = f"{rr.f[i]} -> {rr.t[i]}" if i < len(rr) else ''
        r_ = f"{re_.f[i]} -> {re_.t[i]}" if i < len(re_) else ''
        P(f"{i+1:4d} {l:24s} {rr.excess_ref[i]/1e6 if i < len(rr) else 0:9.1f} {rr.floor_ref[i] if i < len(rr) else 0:5.0f} | "
          f"{r_:24s} {re_.excess_emu[i]/1e6 if i < len(re_) else 0:9.1f} {re_.floor_emu[i] if i < len(re_) else 0:5.0f}")

    # ---- optional: plain basic blocks
    if a.bb_ref and a.bb_emu and a.blocks:
        P('')
        P('4. BASIC BLOCKS  (start address; latency = block commit span)')
        br = pd.read_csv(a.bb_ref, skipinitialspace=True); be = pd.read_csv(a.bb_emu, skipinitialspace=True)
        for d in (br, be):
            d['bb'] = d['bb'].astype(str).str.strip()
            d['start'] = d['bb'].str.split('-').str[0]
        hr = pd.read_csv(a.bb_ref_hist, skipinitialspace=True) if a.bb_ref_hist else None
        he = pd.read_csv(a.bb_emu_hist, skipinitialspace=True) if a.bb_emu_hist else None
        for h in (hr, he):
            if h is not None:
                h['bb'] = h['bb'].astype(str).str.strip()

        def bbmodes(h, bb):
            if h is None:
                return ''
            s = h[h.bb == bb].groupby('cycles')['count'].sum()
            n = s.sum()
            if not n:
                return ''
            return ' '.join(f'{int(c)}c:{100*v/n:.0f}%' for c, v in s.sort_values(ascending=False).head(3).items())

        P(f"{'block':24s} {'n':>12s} | {'mean':>6s} {'p50':>4s} {'p90':>4s} {'modes':>22s} | "
          f"{'mean':>6s} {'p50':>4s} {'p90':>4s} {'modes':>22s}")
        for s in a.blocks.split(','):
            s = s.strip().lower()
            x = br[br.start == s]; y = be[be.start == s]
            if x.empty or y.empty:
                P(f"{s:24s} (missing in {'reference' if x.empty else a.label})")
                continue
            x = x.iloc[0]; y = y.iloc[0]
            P(f"{x.bb:24s} {int(x['count']):12,d} | {x['mean']:6.2f} {int(x.p50):4d} {int(x.p90):4d} {bbmodes(hr, x.bb):>22s} | "
              f"{y['mean']:6.2f} {int(y.p50):4d} {int(y.p90):4d} {bbmodes(he, y.bb):>22s}")

    txt = '\n'.join(out) + '\n'
    Path(f'{a.out}.txt').write_text(txt)
    print(txt)


if __name__ == '__main__':
    main()
