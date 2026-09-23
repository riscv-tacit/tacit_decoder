#!/usr/bin/env python3
"""Stacked bars: how much of a workload's execution time is microarchitectural
variation, and how few basic blocks hold it.

Replaces plot_bb_stats.py (SPEC-only, sqlite `top_by_netvar.csv` + scraped
summary.txt) and draw_vbb.py (hardcoded paths, no CLI). Reads the bb_stats
receiver CSV directly and ranks on vbb, not netvar.

Each bar decomposes total traced cycles into
    sum(count*p5)         near-best-case time -- what the blocks cost on a good day
    vbb of ranks 1..N     variation held by the worst few blocks
    vbb of everything else
since  sum(count*mean) == sum(count*p5) + sum(vbb)  exactly. The denominator is
the CSV itself: block latencies tile the traced window, so sum(count*mean)
reproduces the uartlog's window_cycles (verified to 5 digits on mandelbrot).

  plot_vbb_share.py --out output_vbb/fig.vbb_share --top 5 \
      mandelbrot=output_mandelbrot/trace...bbhist_run.bb_stats.csv \
      sieve=output_vbb/sieve.bb_stats.csv
"""
import argparse
import pathlib
import sys

import matplotlib as mpl
mpl.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.patches import Patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from paper_palette import (MM, SINGLE_COL, NEUTRAL, INK, GRID, ordered, style,
                           fit_tight, save)


def load(path, top, user_only):
    """-> (per-rank vbb list, other vbb, floor cycles, total cycles, top-N frame)."""
    d = pd.read_csv(path, skipinitialspace=True)
    d['bb'] = d['bb'].str.strip()
    d['start'] = d['bb'].str.split('-').str[0]
    if user_only:
        d = d[~d['start'].str.lower().str.startswith('0xffffffff')].copy()

    # vbb = n*(mean-p5): cycles above the block's near-best case. The receiver
    # emits it directly (exact, 1-cycle histogram bins); older CSVs predate the
    # column, and the oldest predate p5 too -- fall back, loudly.
    if 'vbb' not in d.columns:
        if 'p5' in d.columns:
            d['vbb'] = d['count'] * (d['mean'] - d['p5']).clip(lower=0)
            print(f'  note: {path} has no vbb column; recomputed from mean and p5')
        else:
            d['p5'] = d['min']
            d['vbb'] = d['count'] * (d['mean'] - d['min']).clip(lower=0)
            print(f'  WARNING: {path} has no p5; falling back to min, which is one '
                  f'lucky sample and inflates the result. Re-decode this capture.')

    d['cycles'] = d['count'] * d['mean']
    total = d['cycles'].sum()
    d = d.sort_values('vbb', ascending=False).reset_index(drop=True)
    d['rank'] = d.index + 1
    ranked = d.head(top)
    return (ranked['vbb'].tolist(), d['vbb'][top:].sum(),
            total - d['vbb'].sum(), total, ranked, len(d))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('inputs', nargs='+', metavar='LABEL=CSV',
                    help='bb_stats receiver CSVs, in the order to plot them')
    ap.add_argument('--out', required=True, help='prefix: writes <out>.{pdf,png,txt}')
    ap.add_argument('--top', type=int, default=5, help='blocks resolved individually')
    ap.add_argument('--normalize', choices=('cycles', 'vbb'), default='cycles',
                    help='cycles: bars are share of the traced window (default). '
                         'vbb: bars are share of total variation, all reaching 100%%')
    ap.add_argument('--user-only', action='store_true',
                    help='drop kernel blocks; the denominator is then no longer '
                         'the whole traced window')
    ap.add_argument('--width', type=float, default=SINGLE_COL,
                    help='figure width in mm (default: one column, 89)')
    ap.add_argument('--height', type=float, default=58.0, help='figure height in mm')
    a = ap.parse_args()

    labels, data = [], []
    for spec in a.inputs:
        if '=' not in spec:
            raise SystemExit(f'expected LABEL=CSV, got {spec!r}')
        label, path = spec.split('=', 1)
        labels.append(label)
        data.append(load(path, a.top, a.user_only))

    style()
    fig, ax = plt.subplots(figsize=(a.width * MM, a.height * MM))
    # Rank is an ordered quantity, so it gets tints of a single hue at equal
    # luminance steps -- never separate hues, which would imply the ranks are
    # unrelated categories. The pooled tail is the palest step of the same
    # family; only the near-best-case floor, which is not variation at all,
    # switches to the neutral.
    tints = ordered(a.top + 1)
    ramp, c_other = tints[:a.top], tints[a.top]
    x = np.arange(len(labels))

    # Stack variation from the baseline, where heights are read most precisely,
    # and let the near-best-case remainder fill in above it.
    tiers, colors = [], []
    for r in range(a.top):
        tiers.append([d[0][r] if r < len(d[0]) else 0.0 for d in data])
        colors.append(ramp[r])
    tiers.append([d[1] for d in data]); colors.append(c_other)
    if a.normalize == 'cycles':
        tiers.append([d[2] for d in data]); colors.append(NEUTRAL)

    denom = np.array([d[3] if a.normalize == 'cycles' else sum(d[0]) + d[1]
                      for d in data], dtype=float)
    bottom = np.zeros(len(labels))
    for tier, c in zip(tiers, colors):
        h = 100 * np.array(tier) / denom
        ax.bar(x, h, bottom=bottom, width=0.62, color=c,
               edgecolor='white', linewidth=0.35)
        bottom += h

    if a.normalize == 'cycles':
        # One number per bar, at the boundary that carries the claim.
        var = 100 * np.array([sum(d[0]) + d[1] for d in data]) / denom
        for xi, v in zip(x, var):
            ax.text(xi, v + 2.0, f'{v:.0f}%', ha='center', va='bottom',
                    fontsize=5, color=INK)

    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylim(0, 100)
    ax.set_yticks(range(0, 101, 20))
    ax.set_ylabel('Share of total cycles (%)' if a.normalize == 'cycles'
                  else 'Share of total variation (%)')
    ax.set_axisbelow(True)
    ax.yaxis.grid(True, color=GRID, linewidth=0.3)
    ax.spines[['top', 'right']].set_visible(False)

    # Every tier is named outright. A legend title would have to be true of all
    # of them, and the grey is not a block rank -- it is the complement of
    # variation -- so there is no title that covers the set without lying.
    handles = [Patch(facecolor=ramp[r], edgecolor='white', linewidth=0.35,
                     label=f'rank {r + 1} BBv')
               for r in range(a.top)]
    handles.append(Patch(facecolor=c_other, edgecolor='white', linewidth=0.35,
                         label='other BBv aggregated'))
    if a.normalize == 'cycles':
        handles.append(Patch(facecolor=NEUTRAL, edgecolor='white', linewidth=0.35,
                             label='the rest of cycles'))
    ax.legend(handles=handles, ncol=4, loc='upper center',
              bbox_to_anchor=(0.5, -0.10), frameon=False,
              handlelength=1.0, handleheight=0.9, columnspacing=1.2,
              handletextpad=0.35, labelspacing=0.4)

    got_w, got_h = fit_tight(fig, a.width, a.height)
    save(fig, a.out)
    plt.close(fig)

    lines = [
        '=' * 78,
        f'Variation share of execution time   (vbb = n*(mean-p5), top {a.top} resolved)',
        '=' * 78,
        f"blocks: {'user-mode only' if a.user_only else 'all privilege levels'}",
        '',
        f"{'workload':14} {'blocks':>8} {'cycles':>11} {'variation':>11} {'var%':>6} "
        f"{'top%cyc':>8} {'top%var':>8}",
    ]
    for label, d in zip(labels, data):
        ranked_vbb, other, floor, total, ranked, nblocks = d
        tv = sum(ranked_vbb) + other
        lines.append(f'{label:14} {nblocks:8,d} {total/1e9:9.3f} G {tv/1e9:9.3f} G '
                     f'{100*tv/total:5.1f}% {100*sum(ranked_vbb)/total:7.1f}% '
                     f'{100*sum(ranked_vbb)/tv:7.1f}%')
    for label, d in zip(labels, data):
        ranked_vbb, other, floor, total, ranked, nblocks = d
        tv = sum(ranked_vbb) + other
        lines += ['', f'-- {label} ' + '-' * (74 - len(label)),
                  f"{'rank':>4} {'basic block':24} {'executions':>13} {'p5':>5} "
                  f"{'p50':>5} {'p90':>5} {'vbb Mcyc':>10} {'%cyc':>6} {'%var':>6}"]
        for r in ranked.itertuples():
            lines.append(f'{r.rank:4d} {r.bb:24} {int(r.count):13,d} '
                         f'{getattr(r, "p5", float("nan")):5.0f} {r.p50:5.0f} '
                         f'{r.p90:5.0f} {r.vbb/1e6:10.1f} '
                         f'{100*r.vbb/total:5.1f}% {100*r.vbb/tv:5.1f}%')
    txt = '\n'.join(lines) + '\n'
    open(f'{a.out}.txt', 'w').write(txt)
    print(txt)
    print(f'wrote {a.out}.pdf, {a.out}.png and {a.out}.txt '
          f'— {len(labels)} workloads, {got_w:.1f}x{got_h:.1f} mm at final size '
          f'(asked {a.width:.0f}x{a.height:.0f})')


if __name__ == '__main__':
    main()
