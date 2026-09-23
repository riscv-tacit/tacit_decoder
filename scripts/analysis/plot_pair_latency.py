#!/usr/bin/env python3
"""Plot the top pairs from lua_pair_latency_report.py.

One row per (OP0, OP1): the latency of OP1's first basic block when OP0 dispatched into it.
The receiver emits a 5-point summary per pair, so the mark is an interval (min..p99 whisker,
p50..p90 bulk, mean dot) against the predicted-arrival floor -- not a histogram.

  plot_pair_latency.py report.mandelbrot.pairs.csv -o fig_pair_latency.png --top 6
"""
import argparse

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import pandas as pd

SURFACE, INK, INK2, GRID = '#fcfcfb', '#0b0b0b', '#52514e', '#dcdcd6'
CLASS_COLOR = {                      # categorical slots, fixed order, fixed meaning
    'predicted': '#2a78d6',          # slot 1
    'deterministic-miss': '#eb6834', # slot 2
    'interleaving-miss': '#1baf7a',  # slot 3
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('csv')
    ap.add_argument('-o', '--out', default='fig_pair_latency.png')
    ap.add_argument('--top', type=int, default=6)
    ap.add_argument('--title', default='mandelbrot')
    a = ap.parse_args()

    d = pd.read_csv(a.csv)
    d = d[d.n >= 10000].nlargest(a.top, 'mispredict_total').iloc[::-1].reset_index(drop=True)

    fig, ax = plt.subplots(figsize=(9.2, 0.62 * len(d) + 2.35), facecolor=SURFACE)
    ax.set_facecolor(SURFACE)
    for i, r in d.iterrows():
        col = CLASS_COLOR.get(r['class'], INK2)
        ax.plot([r['min'], r['p99']], [i, i], color=col, lw=1, alpha=.45, zorder=2,
                solid_capstyle='round')
        # a deterministic miss has p50 == p90; give the bulk a floor width so the row that
        # matters most does not render as nothing
        lo, hi = r['p50'], max(r['p90'], r['p50'] + 0.30)
        ax.plot([lo, hi], [i, i], color=col, lw=6, alpha=.85, zorder=3,
                solid_capstyle='round')
        ax.plot([r['mean']], [i], 'o', ms=7, color=col, mec=SURFACE, mew=1.6, zorder=5)
        ax.plot([r['floor_p50']], [i], marker='|', ms=13, color=INK2, mew=1.8, zorder=4)

    ax.set_yticks(range(len(d)))
    ax.set_yticklabels([f'{r.op0} → {r.op1}' for r in d.itertuples()],
                       fontsize=10, color=INK, fontweight='bold')
    ax.set_xlabel('cycles in the first basic block of the target handler', color=INK2, fontsize=9.5)
    ax.set_xlim(0, max(d['p99'].max(), d['mean'].max()) * 1.14)
    ax.set_ylim(-0.6, len(d) - 0.4)
    ax.grid(axis='x', color=GRID, lw=.7, zorder=0)
    ax.set_axisbelow(True)
    for s in ('top', 'right', 'left'):
        ax.spines[s].set_visible(False)
    ax.spines['bottom'].set_color(GRID)
    ax.tick_params(colors=INK2, labelsize=9, length=0)

    # structured value column instead of labels scattered over the marks
    xr = ax.get_xlim()[1]
    C1, C2 = xr * 1.045, xr * 1.26
    for i, r in d.iterrows():
        ax.text(C1, i, f"{r['pct_window']:.1f}%", color=INK, fontsize=9.5,
                va='center', ha='right', fontweight='bold', clip_on=False)
        ax.text(C2, i, f"{r['n']/1e6:.0f}M", color=INK2, fontsize=9,
                va='center', ha='right', clip_on=False)
    ax.text(C1, len(d) - 0.28, 'of window', color=INK2, fontsize=8.5, va='center',
            ha='right', clip_on=False)
    ax.text(C2, len(d) - 0.28, 'arrivals', color=INK2, fontsize=8.5, va='center',
            ha='right', clip_on=False)

    handles = [plt.Line2D([], [], color=c, lw=6, solid_capstyle='round', label=k)
               for k, c in CLASS_COLOR.items() if k in set(d['class'])]
    handles += [plt.Line2D([], [], color=INK2, marker='|', ms=11, mew=1.8, ls='none',
                           label='floor: predicted arrival'),
                plt.Line2D([], [], color=INK2, marker='o', ms=7, ls='none', label='mean')]
    ax.legend(handles=handles, loc='upper left', frameon=False, fontsize=8.5,
              labelcolor=INK2, ncol=2, bbox_to_anchor=(0.0, -0.19), columnspacing=2.4,
              handletextpad=.8)

    fig.suptitle(f'Where the dispatch misprediction lands — {a.title}', color=INK,
                 fontsize=12.5, fontweight='bold', x=.012, ha='left', y=.985)
    fig.text(.012, .915, 'Latency of the target handler’s first basic block, conditioned on the handler that '
                         'dispatched into it.\nBar spans p50–p90, whisker min–p99.',
             color=INK2, fontsize=9, ha='left', va='top')
    fig.tight_layout(rect=(0, .06, .84, .87))
    fig.savefig(a.out, dpi=200, facecolor=SURFACE, bbox_inches='tight')
    print(f'wrote {a.out}')


if __name__ == '__main__':
    main()
