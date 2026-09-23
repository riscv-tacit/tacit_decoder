#!/usr/bin/env python3
"""Per-pair entry-block latency report: the misprediction, attributed correctly.

The fix we are designing acts on the PREDECESSOR (make OP0's dispatch adapt to a known
successor), but the cost it removes is charged to the SUCCESSOR: a mispredicted dispatch
out of OP0 stalls the front end, and those cycles land in OP1's first basic block. So the
quantity to report is

    latency of OP1's first basic block, conditioned on OP0

which is exactly what the dispatch_stats receiver measures (arrival timestamp -> first
control-flow event inside the target). A per-block profile that does NOT condition on the
predecessor reports a mixture of these and hides the mechanism; the `target` report below
quantifies how much it hides.

  lua_pair_latency_report.py --optab configs/lua/lua_optab_fusebase.json \
      --stats trace.lua-fuse-base-mandelbrot.dispatch_stats.csv --window 6.543 \
      --out report.mandelbrot

Writes <out>.pairs.csv and <out>.targets.csv.

NOTE ON GRANULARITY: the receiver emits count/mean/min/p50/p90/p99/max per pair, so the
"distribution" here is a 5-point summary, not a histogram. Full histograms need ~20 lines
in dispatch_stats_receiver.rs (bucket `records` before the flush); there is no cargo on
this account to rebuild the decoder.
"""
import argparse
import json

import pandas as pd

MIN_N = 10000          # a floor must not be set by a handful of samples
DET_SPREAD = 2         # p90 - p50 <= this  => the cost is the same on essentially every arrival
MIN_GAP = 5            # p50 - floor >= this => there is something to recover


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--optab', required=True)
    ap.add_argument('--stats', required=True)
    ap.add_argument('--window', type=float, required=True, help='guest window, seconds (1 GHz target)')
    ap.add_argument('--floor-extra', action='append', default=[], metavar='CSV',
                    help='other captures (same binary) to pool the per-target floor from. A '
                         'handler that this workload NEVER predicts has no cheap arrival of '
                         'its own, so its local floor equals its miss cost and the whole '
                         'opportunity reads as zero.')
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    optab = json.load(open(a.optab))
    W = a.window * 1e9

    d = pd.read_csv(a.stats, skipinitialspace=True)
    for c in ('from_handler', 'to_handler'):
        d[c] = d[c].str.strip()
    d['op0'] = d['from_handler'].map(optab)
    d['op1'] = d['to_handler'].map(optab)
    unmapped = int(d['count'][d['op0'].isna() | d['op1'].isna()].sum())
    d = d.dropna(subset=['op0', 'op1']).copy()
    d = d.rename(columns={'count': 'n'})
    d['sum_cyc'] = d['n'] * d['mean']

    g = d.groupby(['op0', 'op1'], as_index=False).agg(
        n=('n', 'sum'), sum_cyc=('sum_cyc', 'sum'), min=('min', 'min'), p50=('p50', 'median'),
        p90=('p90', 'median'), p99=('p99', 'median'), max=('max', 'max'))
    g['mean'] = g['sum_cyc'] / g['n']

    # floor for a target = its cheapest MEDIAN arrival over hot predecessors: the cost of
    # this first BB when the dispatch into it was predicted. min-of-min is an extreme value
    # and drifts ~10% between identical runs; the median does not.
    # ---- per-target floor: the cost of this first BB when the dispatch into it was
    # predicted. Estimated as the cheapest MEDIAN arrival over hot predecessors (min-of-min
    # is a single-sample extreme and drifts ~10% between identical runs).
    def target_floors(df):
        return df[df.n >= MIN_N].groupby('op1')['p50'].min()

    floors = {'(this workload)': target_floors(g)}
    for extra in a.floor_extra:
        e = pd.read_csv(extra, skipinitialspace=True)
        for c in ('from_handler', 'to_handler'):
            e[c] = e[c].str.strip()
        e['op1'] = e['to_handler'].map(optab)
        e = e.dropna(subset=['op1']).rename(columns={'count': 'n'})
        floors[extra] = e[e.n >= MIN_N].groupby('op1')['p50'].min()

    fl = pd.DataFrame(floors)
    floor_tbl = pd.DataFrame({
        'floor_p50': fl.min(axis=1),
        'floor_local_p50': fl['(this workload)'],
        'floor_captures': fl.notna().sum(axis=1),
    })
    floor_tbl['floor_hidden_locally'] = (
        floor_tbl['floor_local_p50'] - floor_tbl['floor_p50'] > 2)
    g = g.merge(floor_tbl, left_on='op1', right_index=True, how='left')
    g['floor_captures'] = g['floor_captures'].fillna(0).astype(int)
    g['mispredict_cyc'] = (g['mean'] - g['floor_p50']).clip(lower=0)
    g['mispredict_total'] = g['n'] * g['mispredict_cyc']
    g['pct_window'] = 100 * g['mispredict_total'] / W
    g['spread_p90_p50'] = g['p90'] - g['p50']
    g['tail_p99_p50'] = g['p99'] - g['p50']
    tot_to = g.groupby('op1')['n'].sum().rename('n_op1_total')
    tot_from = g.groupby('op0')['n'].sum().rename('n_op0_total')
    g = g.merge(tot_to, on='op1').merge(tot_from, on='op0')
    g['share_of_op1_arrivals'] = g['n'] / g['n_op1_total']
    g['share_of_op0_exits'] = g['n'] / g['n_op0_total']

    def cls(r):
        # classify on the WHOLE distribution, not on p50 alone: an edge whose p50 sits at the
        # floor but whose p90 is 19 is mispredicted half the time, not "predicted".
        if r['n'] < MIN_N or pd.isna(r['floor_p50']):
            return 'rare'
        if r['p90'] - r['floor_p50'] < MIN_GAP:
            return 'predicted'
        if r['spread_p90_p50'] <= DET_SPREAD and r['p50'] - r['floor_p50'] >= MIN_GAP:
            return 'deterministic-miss'
        return 'interleaving-miss'
    g['class'] = g.apply(cls, axis=1)

    cols = ['op0', 'op1', 'n', 'share_of_op0_exits', 'share_of_op1_arrivals',
            'min', 'p50', 'p90', 'p99', 'max', 'mean', 'floor_p50', 'floor_local_p50',
            'floor_hidden_locally', 'floor_captures',
            'mispredict_cyc', 'mispredict_total', 'pct_window',
            'spread_p90_p50', 'tail_p99_p50', 'class']
    pairs = g[cols].sort_values('mispredict_total', ascending=False)
    pairs.to_csv(f'{a.out}.pairs.csv', index=False, float_format='%.3f')

    # what a per-block profile WITHOUT predecessor context would report for each target
    hot = g[g.n >= MIN_N]
    t = hot.groupby('op1').apply(lambda x: pd.Series({
        'n_arrivals': x['n'].sum(),
        'n_predecessors': len(x),
        'blended_mean': (x['n'] * x['mean']).sum() / x['n'].sum(),
        'best_pred_p50': x['p50'].min(),
        'worst_pred_p50': x['p50'].max(),
        'p50_spread': x['p50'].max() - x['p50'].min(),
        'hidden_cyc_per_arrival': (x['n'] * x['mean']).sum() / x['n'].sum() - x['p50'].min(),
        'hidden_total': ((x['n'] * x['mean']).sum() / x['n'].sum() - x['p50'].min()) * x['n'].sum(),
    }), include_groups=False).reset_index()
    t['hidden_pct_window'] = 100 * t['hidden_total'] / W
    t = t.sort_values('hidden_total', ascending=False)
    t.to_csv(f'{a.out}.targets.csv', index=False, float_format='%.3f')

    print(f'unmapped events: {unmapped:,}')
    print(f'{len(pairs)} pairs -> {a.out}.pairs.csv')
    print(f'{len(t)} targets -> {a.out}.targets.csv')
    tot = g[g.n >= MIN_N]['mispredict_total'].sum()
    print(f'total attributable misprediction: {tot/1e9:.3f} Gcyc = {100*tot/W:.1f}% of the window')
    print(g[g.n >= MIN_N].groupby('class')['mispredict_total'].agg(
        ['size', 'sum']).assign(pct=lambda x: 100 * x['sum'] / tot).to_string())


if __name__ == '__main__':
    main()
