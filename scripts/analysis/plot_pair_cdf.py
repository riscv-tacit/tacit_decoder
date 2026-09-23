#!/usr/bin/env python3
"""CDF of the entry-block latency for the top (OP0 -> OP1) pairs.

Input is the true per-instance histogram from pair_hist_from_events.sh, not a quantile
summary. One panel per pair; the vertical rule is the floor (what this target's first block
costs when the dispatch into it was predicted).

  plot_pair_cdf.py mandelbrot.hist.csv --pairs-csv report.mandelbrot.pairs.csv -o fig.png
"""
import argparse

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

SURFACE, INK, INK2, GRID = '#fcfcfb', '#0b0b0b', '#52514e', '#dcdcd6'
CLASS_COLOR = {'predicted': '#2a78d6', 'deterministic-miss': '#eb6834',
               'interleaving-miss': '#1baf7a'}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('hist')
    ap.add_argument('--pairs-csv', required=True)
    ap.add_argument('-o', '--out', default='fig_pair_cdf.png')
    ap.add_argument('--top', type=int, default=6)
    ap.add_argument('--xmax', type=float, default=40)
    ap.add_argument('--optab', help='needed when the hist CSV uses hex handler addresses')
    ap.add_argument('--title', default='mandelbrot')
    a = ap.parse_args()

    h = pd.read_csv(a.hist)
    # accept the receiver's native dump (hex handler addresses) as well as the
    # op-name form produced by pair_hist_from_events.sh
    if 'from_handler' in h.columns:
        import json as _json
        if not a.optab:
            ap.error('--optab is required for a receiver hist CSV (hex handler addresses)')
        nm = _json.load(open(a.optab))
        for src, dst in (('from_handler', 'op0'), ('to_handler', 'op1')):
            h[dst] = h[src].str.strip().map(nm)
        h = h.dropna(subset=['op0', 'op1'])
    meta = pd.read_csv(a.pairs_csv)
    meta = meta[meta.n >= 10000].nlargest(a.top, 'mispredict_total')

    rows = int(np.ceil(len(meta) / 3))
    fig, axes = plt.subplots(rows, 3, figsize=(11.6, 3.15 * rows), facecolor=SURFACE,
                             sharex=True, sharey=True)
    axes = np.atleast_1d(axes).ravel()
    for ax, (_, r) in zip(axes, meta.iterrows()):
        g = h[(h.op0 == r['op0']) & (h.op1 == r['op1'])].sort_values('cycles')
        col = CLASS_COLOR.get(r['class'], INK2)
        ax.set_facecolor(SURFACE)
        if len(g):
            cyc = g['cycles'].to_numpy(float)
            cdf = np.cumsum(g['count'].to_numpy(float))
            cdf /= cdf[-1]
            ax.step(cyc, cdf, where='post', color=col, lw=2.2, zorder=4)
            ax.fill_between(cyc, 0, cdf, step='post', color=col, alpha=.12, zorder=3)
            n = int(g['count'].sum())
        else:
            n = 0
        ax.axvline(r['floor_p50'], color=INK2, lw=1.2, ls=(0, (3, 3)), zorder=2)
        ax.set_title(f"{r['op0']} → {r['op1']}", color=INK, fontsize=10.5,
                     fontweight='bold', loc='left', pad=7)
        # bottom-right is empty in a CDF panel; keeps the caption off the title and the curve
        ax.text(.97, .06, f"{n/1e6:.1f}M instances\n{r['pct_window']:.1f}% of window",
                transform=ax.transAxes, color=INK2, fontsize=8.4, va='bottom', ha='right')
        ax.set_xlim(0, a.xmax)
        ax.set_ylim(0, 1.04)
        ax.grid(color=GRID, lw=.7, zorder=0)
        ax.set_axisbelow(True)
        for s in ('top', 'right'):
            ax.spines[s].set_visible(False)
        for s in ('left', 'bottom'):
            ax.spines[s].set_color(GRID)
        ax.tick_params(colors=INK2, labelsize=8.5)
    for ax in axes[len(meta):]:
        ax.set_visible(False)
    for ax in axes[-3:]:
        ax.set_xlabel('cycles in the target’s first basic block', color=INK2, fontsize=9)
    for i in range(0, len(axes), 3):
        axes[i].set_ylabel('cumulative share', color=INK2, fontsize=9)

    handles = [plt.Line2D([], [], color=c, lw=2.4, label=k) for k, c in CLASS_COLOR.items()
               if k in set(meta['class'])]
    handles += [plt.Line2D([], [], color=INK2, lw=1.2, ls=(0, (3, 3)),
                           label='floor: predicted arrival')]
    fig.legend(handles=handles, loc='lower left', bbox_to_anchor=(.012, .002), ncol=4,
               frameon=False, fontsize=8.8, labelcolor=INK2)
    fig.suptitle(f'Dispatch misprediction is a step function, not a spread — {a.title}',
                 color=INK, fontsize=12.5, fontweight='bold', x=.012, ha='left', y=.985)
    fig.text(.012, .93, 'Per-instance latency of the target handler’s first basic block, '
                        'conditioned on the handler that dispatched into it.',
             color=INK2, fontsize=9, ha='left', va='top')
    fig.tight_layout(rect=(0, .06, 1, .90))
    fig.savefig(a.out, dpi=200, facecolor=SURFACE)
    print(f'wrote {a.out}')


if __name__ == '__main__':
    main()
