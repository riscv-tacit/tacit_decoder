#!/usr/bin/env python3
"""Figure: the cost of entering a bytecode handler is set by which handler dispatched into it.

Each row is one target handler, so the work along the row is identical by construction.
Each curve is one predecessor's latency distribution for that handler's first basic block.
Colours are per row: the three highest-traffic predecessors get distinct colours, anything
else is grey. Baseline only -- no intervention.

  plot_dispatch_phenomenon.py report.mandelbrot.pairs.csv --hist mandelbrot.hist.csv \
      -o fig.png --title mandelbrot
"""
import argparse

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

SURFACE, INK, INK2, GRID = '#fcfcfb', '#0b0b0b', '#52514e', '#dcdcd6'
SERIES = ['#2a78d6', '#eb6834', '#1baf7a']   # categorical slots 1-3, fixed order
OTHER = '#cfcec7'
ROW_H = 0.78


def density(sub, sigma, grid):
    y = np.zeros_like(grid, dtype=float)
    for c, k in zip(sub['cycles'].to_numpy(float), sub['count'].to_numpy(float)):
        if c <= grid[-1]:
            y += k * np.exp(-0.5 * ((grid - c) / sigma) ** 2) if sigma > 0 else 0
            if sigma <= 0:
                y[int(round(c))] += k
    return y


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('pairs_csv')
    ap.add_argument('-o', '--out', default='fig_phenomenon.png')
    ap.add_argument('--hist')
    ap.add_argument('--optab', help='needed when --hist uses hex handler '
                                    'addresses (the receiver dump does)')
    ap.add_argument('--title', default='')
    ap.add_argument('--min-n', type=int, default=10000)
    ap.add_argument('--max-rows', type=int, default=7)
    ap.add_argument('--xmax', type=float, default=0, help='0 = auto')
    ap.add_argument('--smooth', type=float, default=0.7)
    a = ap.parse_args()

    d = pd.read_csv(a.pairs_csv)
    d = d[d.n >= a.min_n].copy()
    hist = pd.read_csv(a.hist) if a.hist else None
    if hist is not None and 'from_handler' in hist.columns:
        # the receiver's own dump keys on hex handler addresses; the awk extraction on names
        if not a.optab:
            ap.error('--optab is required for a receiver hist CSV')
        import json as _json
        nm = _json.load(open(a.optab))
        for src, dst in (('from_handler', 'op0'), ('to_handler', 'op1')):
            hist[dst] = hist[src].str.strip().map(nm)
        hist = hist.dropna(subset=['op0', 'op1'])

    rows = [(t, g) for t, g in d.groupby('op1') if len(g) >= 2]
    rows.sort(key=lambda x: -x[1]['mispredict_total'].sum())
    rows = rows[:a.max_rows][::-1]

    xmax = a.xmax or float(d['p99'].max() * 1.05)
    grid = np.arange(0, int(xmax) + 1, dtype=float)
    legend_x = xmax * 1.05                      # right margin holds the per-row key

    fig, ax = plt.subplots(figsize=(10.6, 0.86 * len(rows) + 1.7), facecolor=SURFACE)
    ax.set_facecolor(SURFACE)

    for i, (t, g) in enumerate(rows):
        g = g.sort_values('n', ascending=False).reset_index(drop=True)
        colours = {r['op0']: (SERIES[j] if j < len(SERIES) else OTHER)
                   for j, r in g.iterrows()}
        ax.plot([0, xmax], [i, i], color=GRID, lw=.8, zorder=2)

        if hist is not None:
            sub_all = hist[hist.op1 == t]
            curves = []
            for _, r in g.iterrows():
                sub = sub_all[sub_all.op0 == r['op0']]
                if len(sub):
                    y = density(sub, a.smooth, grid)
                    if y.sum() > 0:
                        curves.append((r['op0'], y / y.sum() * (r['n'] / g['n'].sum())))
            if curves:
                peak = max(y.max() for _, y in curves)
                for op0, y in curves:
                    yy = i + ROW_H * y / peak
                    vis = y > y.max() * 0.004
                    ax.fill_between(grid, i, yy, where=vis, color=colours[op0],
                                    alpha=.26, lw=0, zorder=3)
                    ax.plot(np.where(vis, grid, np.nan), np.where(vis, yy, np.nan),
                            color=colours[op0], lw=1.7, zorder=4)
        else:
            for _, r in g.iterrows():
                ax.plot([r['p50']], [i + .12], marker='o', ms=8, color=colours[r['op0']],
                        mec=SURFACE, mew=1.2, zorder=4)

        ax.plot([g['floor_p50'].iloc[0]], [i], marker='|', ms=13, color=INK2, mew=1.8, zorder=6)

        # per-row key: colour -> predecessor, stacked so long names cannot collide
        for j, (_, r) in enumerate(g.iterrows()):
            if j >= len(SERIES):
                break
            y = i + ROW_H * (0.80 - 0.30 * j)
            ax.plot([legend_x], [y], marker='s', ms=7, color=colours[r['op0']], zorder=6,
                    clip_on=False)
            ax.annotate(r['op0'], xy=(legend_x, y), xytext=(9, 0), textcoords='offset points',
                        va='center', ha='left', color=INK2, fontsize=8.5,
                        annotation_clip=False)

    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([t for t, _ in rows], fontsize=11, color=INK, fontweight='bold')
    ax.set_xlabel('cycles in the target handler’s first basic block', color=INK2, fontsize=9.5)
    ax.set_xlim(0, xmax)
    ax.set_ylim(-.30, len(rows) - 1 + ROW_H + .25)
    ax.grid(axis='x', color=GRID, lw=.7, zorder=0)
    ax.set_axisbelow(True)
    for s in ('top', 'right', 'left'):
        ax.spines[s].set_visible(False)
    ax.spines['bottom'].set_color(GRID)
    ax.tick_params(colors=INK2, labelsize=9, length=0)

    ax.legend(handles=[plt.Line2D([], [], marker='|', ls='none', ms=11, mew=1.8, color=INK2,
                                  label='cost when the dispatch is predicted')],
              loc='upper right', bbox_to_anchor=(1.0, -0.09), frameon=False,
              fontsize=8.5, labelcolor=INK2)
    if a.title:
        ax.set_title(a.title, color=INK, fontsize=11, fontweight='bold', loc='left', pad=10)
    fig.subplots_adjust(left=.095, right=.80, top=.93, bottom=.16)
    fig.savefig(a.out, dpi=200, facecolor=SURFACE)
    print(f'wrote {a.out} ({len(rows)} rows)')


if __name__ == '__main__':
    main()
