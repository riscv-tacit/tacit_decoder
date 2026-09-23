#!/usr/bin/env python3
"""Publication figure: latency distributions of the basic blocks that vary most.

Unconditioned view -- blocks ranked by vbb = n*(mean-p5), each panel showing that block's
measured latency histogram. Built at final print size per Nature artwork specs.

  plot_bb_distributions.py --bb-stats <bb_stats.csv> --bb-hist <bb_hist.csv> \
      --optab <optab.json> -o fig.pdf --top 6
"""
import argparse
import json
import pathlib
import string
import sys

import matplotlib as mpl
mpl.use('Agg')
import matplotlib.patheffects as pe
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from paper_palette import (MM, SINGLE_COL, DOUBLE_COL, MAX_HEIGHT, NAVY, CORAL,
                           INK, INK2, style, fit_tight)

MAX_PANELS = 3           # panels share their row with the legend
LEGEND_FRAC = 0.40       # legend column width, as a fraction of a panel
BAR = NAVY               # the data itself takes the main series colour
# Percentiles are an ordered set, so they are one hue, never five: coral is the
# figure's single accent and the dash pattern carries which percentile it is.
# Position helps too -- they always appear in order along x. Each line gets a
# white casing so it reads on the navy bars and on the white gaps between them.
PCTL = {                       # percentile -> (colour, dash, label)
    5:  (CORAL, (0, (1, 1.2)),            'p5'),
    25: (CORAL, (0, (1, 1.2, 3, 1.2)),    'p25'),
    50: (CORAL, (0, ()),                  'p50'),
    90: (CORAL, (0, (3.5, 1.4)),          'p90'),
    99: (CORAL, (0, (5.5, 1.4, 1, 1.4)),  'p99'),
}

style(**{
    'axes.titlesize': 6.5,
    'xtick.major.size': 2.5, 'ytick.major.size': 2.5,
    'axes.labelcolor': INK, 'xtick.color': INK2, 'ytick.color': INK2,
    'axes.edgecolor': INK2,
    'figure.constrained_layout.use': True,
    'figure.constrained_layout.h_pad': 0.02,
    'figure.constrained_layout.w_pad': 0.02,
    'figure.constrained_layout.hspace': 0.14,   # breathing room between panel rows
    'figure.constrained_layout.wspace': 0.05,
})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bb-stats', required=True)
    ap.add_argument('--bb-hist', required=True)
    ap.add_argument('--optab')
    ap.add_argument('-o', '--out', default='fig_bb_dist.pdf')
    ap.add_argument('--top', type=int, default=6)
    ap.add_argument('--cols', type=int, default=3)
    ap.add_argument('--width', choices=('single', 'double'), default='double')
    ap.add_argument('--panel-height', type=float, default=34.0, help='mm per panel row')
    ap.add_argument('--percentiles', default='50,90,99',
                    help='percentile markers to draw, e.g. 5,50,90,99')
    ap.add_argument('--min-range', type=float, default=0,
                    help='omit blocks whose p5-p90 range is under this many cycles. A '
                         'DISPLAY filter: such blocks are bound by commit-slot '
                         'quantisation, so their vbb is real but has no shape to plot.')
    ap.add_argument('--blocks',
                    help='plot exactly these blocks, comma separated, in this order, max 3 '
                         '(start address or full start-end). Overrides --top/--min-range: '
                         'the selection is then editorial, so caption them as SELECTED '
                         'blocks, not as the top N.')
    a = ap.parse_args()
    if a.blocks and len([x for x in a.blocks.split(',') if x.strip()]) > MAX_PANELS:
        raise SystemExit(f'--blocks takes at most {MAX_PANELS}; the legend shares their row')

    tab = {k.lower(): v for k, v in json.load(open(a.optab)).items()} if a.optab else {}
    b = pd.read_csv(a.bb_stats, skipinitialspace=True)
    b['bb'] = b['bb'].str.strip()
    b['start'] = b['bb'].str.split('-').str[0]
    b = b[~b['start'].str.lower().str.startswith('0xffffffff')].copy()
    if 'vbb' not in b.columns:
        floor = b['p5'] if 'p5' in b.columns else b['min']
        b['vbb'] = b['count'] * (b['mean'] - floor).clip(lower=0)
    total_vbb = b['vbb'].sum()
    if a.min_range:
        b = b[(b['p90'] - b['p5']) >= a.min_range]
    b = b.sort_values('vbb', ascending=False)

    h = pd.read_csv(a.bb_hist)
    h['bb'] = h['bb'].str.strip()
    have = set(h['bb'])
    # Warn only when a block that WOULD have been shown has no histogram, i.e. the dump
    # actually displaced a panel. Blocks further down the ranking are irrelevant: they were
    # never going to be plotted, so their absence from the dump is not a defect.
    if a.blocks:
        # Explicit selection: no ranking, no range filter. Match on the start address so
        # the caller need not know the end, and keep the order they asked for.
        rank = {bb: i + 1 for i, bb in enumerate(b['bb'])}
        by_start = {r.start.lower(): r.bb for r in b.itertuples()}
        picked = []
        for tok in (x.strip() for x in a.blocks.split(',') if x.strip()):
            key = tok.lower().split('-')[0]
            bb = by_start.get(key)
            if bb is None:
                raise SystemExit(f'{tok}: no such user-mode block in {a.bb_stats}')
            if bb not in have:
                raise SystemExit(f'{tok}: no histogram in {a.bb_hist}; add it to hist_bbs '
                                 f'or raise hist_top and re-decode')
            picked.append(bb)
        b = b.set_index('bb').loc[picked].reset_index()
        print('selected blocks (vbb rank in parentheses): ' +
              ', '.join(f'{bb} ({rank[bb]})' for bb in picked))
    else:
        # Warn only when a block that WOULD have been shown has no histogram, i.e. the dump
        # actually displaced a panel. Blocks further down the ranking are irrelevant.
        ideal = list(b['bb'].head(a.top))
        b = b[b['bb'].isin(have)].head(a.top)
        displaced = [x for x in ideal if x not in have]
        if displaced:
            print(f'WARNING: {len(displaced)} block(s) in the top {a.top} have no histogram '
                  f'in the dump, so lower-ranked blocks are shown instead: {displaced}. '
                  f'Raise hist_top in the decode config and re-decode.')

    want = [int(x) for x in a.percentiles.split(',') if x.strip()]
    n = len(b)
    if a.blocks:
        # Everything on one row, legend in the trailing cell, so a 3-panel figure reads
        # as a single strip rather than a grid with a hole in it.
        cols, rows = n + 1, 1
    else:
        cols = min(a.cols, n)
        # reserve one cell for the legend; it goes in the slot the panels leave empty
        rows = int(np.ceil((n + 1) / cols))
    width = (DOUBLE_COL if a.width == 'double' else SINGLE_COL) * MM
    height = min(rows * a.panel_height + 6, MAX_HEIGHT) * MM
    # The legend needs far less width than a panel, so shrink its column rather
    # than letting it claim an equal share of the row.
    gs = {'width_ratios': [1.0] * n + [LEGEND_FRAC]} if a.blocks else None
    fig, axes = plt.subplots(rows, cols, figsize=(width, height), gridspec_kw=gs)
    axes = np.atleast_1d(axes).ravel()

    for idx, (ax, r) in enumerate(zip(axes, b.itertuples())):
        g = h[h.bb == r.bb].sort_values('cycles')
        # per-panel x range: one block's slow mode sits at 68 cycles while another's whole
        # range is 2-10, and a shared axis hides whichever is not the majority
        xmax = max(8.0, float(r.p99) * 1.35)
        cyc = g['cycles'].to_numpy(float)
        cnt = g['count'].to_numpy(float)
        share = cnt / cnt.sum()
        keep = cyc <= xmax
        ax.bar(cyc[keep], share[keep], width=1.0, color=BAR, linewidth=0, zorder=2)
        for q in want:
            colour, dash, _ = PCTL[q]
            ax.axvline(getattr(r, f'p{q}'), color=colour, ls=dash, zorder=4,
                       lw=0.9 if q == 50 else 0.7,
                       path_effects=[pe.withStroke(linewidth=0.5, foreground='white')])

        name = tab.get(r.start.lower(), '')
        ax.set_title(f'{r.bb}', loc='left', color=INK, pad=2)
        # Percentile markers span the full panel height, so this label sits on top
        # of them wherever it lands; a white plate keeps it readable rather than
        # chasing a gap that differs from panel to panel.
        ax.text(0.97, 0.92, f'$n$ = {r.count/1e6:.1f} $\\times$ 10$^6$',
                transform=ax.transAxes, ha='right', va='top', color=INK2, fontsize=5,
                zorder=6, bbox=dict(facecolor='white', edgecolor='none',
                                    boxstyle='square,pad=0.18'))
        ax.text(-0.22, 1.12, string.ascii_lowercase[idx], transform=ax.transAxes,
                fontsize=8, fontweight='bold', va='top', ha='left', color=INK)
        ax.set_xlim(0, xmax)
        ax.set_ylim(0, max(share) * 1.18)
        ax.spines[['top', 'right']].set_visible(False)
        ax.tick_params(length=2.5, pad=1.5)
        if idx % cols == 0:
            ax.set_ylabel('Share of executions')
        # every panel gets its own x label: the axes are not shared, since one block's slow
        # mode sits near 68 cycles while another's whole range is 2-10
        ax.set_xlabel('Block latency (cycles)')

    # legend in the free cell, keyed by colour AND dash so it survives grayscale
    legend_ax = axes[n]
    legend_ax.set_axis_off()
    handles = [plt.Line2D([], [], color=PCTL[q][0], ls=PCTL[q][1],
                          lw=0.9 if q == 50 else 0.7, label=PCTL[q][2]) for q in want]
    handles.append(plt.Line2D([], [], color=BAR, lw=3.2, label='Latency distribution'))
    legend_ax.legend(handles=handles, loc='center left', frameon=False,
                     handlelength=1.6, handletextpad=0.5, labelspacing=0.5, borderpad=0)
    for ax in axes[n + 1:]:
        ax.set_visible(False)

    out = a.out
    got_w, got_h = fit_tight(fig, width / MM, height / MM, 0.03)
    fig.savefig(out, bbox_inches='tight', pad_inches=0.03)
    png = out.rsplit('.', 1)[0] + '.png'
    fig.savefig(png, dpi=300, bbox_inches='tight', pad_inches=0.03)
    print(f'wrote {out} and {png} — {n} panels, '
          f'{got_w:.1f}x{got_h:.1f} mm at final size')


if __name__ == '__main__':
    main()
