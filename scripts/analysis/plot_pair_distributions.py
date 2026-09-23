#!/usr/bin/env python3
"""Figure: the cost of a dispatch is set by the PREDECESSOR, not the site.

For a fixed (handler, successor) context, the handler does identical work and leaves by
the identical exit -- so the only thing distinguishing the instances is which handler ran
before it. Per-instance latencies come from dispatch_seq timestamps (arrival to arrival),
about a million samples per curve.

  plot_pair_distributions.py --optab configs/lua/lua_optab_fusebase.json -o pair_dist.png
"""
import argparse
import json

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

# surface + ink (dataviz reference palette, light mode)
SURFACE, INK, INK2, GRID = '#fcfcfb', '#0b0b0b', '#52514e', '#dcdcd6'
# categorical slots 1 and 2, used with a consistent meaning in every panel:
# blue = the predecessor that arrives cheaply, orange = the one that does not
FAST, SLOW = '#2a78d6', '#eb6834'

PANELS = [
    # bench, seq csv, handler, successor, (cheap predecessor, costly predecessor)
    ('mandelbrot', 'trace.lua-fuse-base-mandelbrot.dispatch_seq.csv', 'MUL', 'ADD', ('MULK', 'MUL')),
    ('spectralnorm', 'trace.lua-fuse-base-spectralnorm.dispatch_seq.csv', 'ADD', 'ADDI', ('DIVK', 'ADD')),
    ('fannkuch', 'trace.lua-fuse-base2-fannkuch.dispatch_seq.csv', 'GETTABLE', 'SETTABLE', ('FORLOOP', 'GETTABLE')),
]


def series(csv, nm, J, K, preds, nrows):
    d = pd.read_csv(csv, nrows=nrows)
    ts = d['timestamp'].to_numpy(np.int64)
    h = d['to_handler'].str.strip().map(lambda s: int(s, 16)).map(nm).astype('category')
    c = h.cat.codes.to_numpy()
    cats = list(h.cat.categories)
    idx = {n: i for i, n in enumerate(cats)}
    dt = np.diff(ts)[1:]
    prev, cur, nxt = c[:-2], c[1:-1], c[2:]
    sel = (cur == idx[J]) & (nxt == idx[K])
    out = []
    for p in preds:
        v = dt[sel & (prev == idx[p])]
        out.append((p, v[v < 300]))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--optab', required=True)
    ap.add_argument('-o', '--out', default='pair_dist.png')
    ap.add_argument('--nrows', type=int, default=20_000_000)
    a = ap.parse_args()
    nm = {int(k, 16): v for k, v in json.load(open(a.optab)).items()}

    fig, axes = plt.subplots(1, 3, figsize=(12.6, 4.1), facecolor=SURFACE)
    bins = np.arange(0, 51)
    for ax, (bench, csv, J, K, preds) in zip(axes, PANELS):
        data = series(csv, nm, J, K, preds, a.nrows)
        ax.set_facecolor(SURFACE)
        peak = max(np.histogram(v, bins=bins, weights=np.ones(len(v)) / len(v))[0].max()
                   for _, v in data)
        meds = []
        for (name, v), col, ylab in zip(data, (FAST, SLOW), (.80, .60)):
            w = np.ones(len(v)) / len(v)
            ax.hist(v, bins=bins, weights=w, histtype='stepfilled', lw=1.6,
                    color=col, alpha=.18, edgecolor=col, zorder=3)
            med = float(np.median(v)); meds.append(med)
            ax.axvline(med, color=col, lw=1, ls=(0, (2, 2)), alpha=.8, zorder=2)
            # label sits beside its own peak, clear of the title band and of the other series
            side = 'left' if med < 25 else 'right'
            xoff = 3 if side == 'left' else -3
            # identity travels on a colored mark; the text itself stays in ink (contrast)
            ha = 'left' if side == 'left' else 'right'
            ax.annotate('\u25a0', xy=(med, peak * ylab), xytext=(xoff, 0),
                        textcoords='offset points', color=col, fontsize=9,
                        ha=ha, va='center', zorder=5)
            ax.annotate(f'  after {name}\n  {len(v)/1e3:.0f}k inst · p50 {med:.0f} cyc'
                        if ha == 'left' else
                        f'after {name}  \n{len(v)/1e3:.0f}k inst · p50 {med:.0f} cyc  ',
                        xy=(med, peak * ylab), xytext=(xoff + (9 if ha == 'left' else -9), 0),
                        textcoords='offset points', color=INK, fontsize=8.5, fontweight='bold',
                        ha=ha, va='center', zorder=5)
        lo, hi = sorted(meds)
        ax.annotate('', xy=(lo, peak * .30), xytext=(hi, peak * .30),
                    arrowprops=dict(arrowstyle='<->', color=INK2, lw=1.1), zorder=4)
        ax.annotate(f'{hi-lo:.0f} cycles, identical work', xy=((lo + hi) / 2, peak * .33),
                    ha='center', va='bottom', color=INK2, fontsize=8.5, zorder=5)
        ax.set_title(f'{bench}  ·  {J} \u2192 {K}', color=INK, fontsize=10.5,
                     fontweight='bold', loc='left', pad=6)
        ax.set_xlabel('cycles in the handler', color=INK2, fontsize=9)
        ax.set_xlim(0, 50)
        ax.set_ylim(0, peak * 1.06)
        ax.grid(axis='y', color=GRID, lw=.7, zorder=0)
        ax.set_axisbelow(True)
        for sp in ('top', 'right'):
            ax.spines[sp].set_visible(False)
        for sp in ('left', 'bottom'):
            ax.spines[sp].set_color(GRID)
        ax.tick_params(colors=INK2, labelsize=8.5)
    axes[0].set_ylabel('share of instances', color=INK2, fontsize=9)
    fig.suptitle('One interpreter handler, one successor: the cost is set by which handler ran before it',
                 color=INK, fontsize=12.5, fontweight='bold', x=.010, ha='left', y=.985)
    fig.text(.010, .905,
             'Per-instance dispatch latency. In each panel the handler and its successor are fixed, so the work is identical; '
             'only the preceding handler differs.\nFireSim MegaBoom v3, Lua 5.4.7 built with -fno-crossjumping (one dispatch site per handler exit).',
             color=INK2, fontsize=8.8, ha='left', va='top')
    fig.tight_layout(rect=(0, 0, 1, .855))
    fig.savefig(a.out, dpi=200, facecolor=SURFACE)
    print(f'wrote {a.out}')


if __name__ == '__main__':
    main()
