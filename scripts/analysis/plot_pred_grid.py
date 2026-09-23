#!/usr/bin/env python3
"""Per-predecessor latency of a handler's entry block, before and after each patch.

Rows are target blocks, columns are interpreter arms. The point is to read one row
left to right and see a predecessor removed, so three things have to hold that the
single-arm plotter got wrong:

  colour follows IDENTITY, not rank.  Colour is assigned to the predecessor's
      OPCODE, from the union of predecessors across all arms for that row, ordered
      by total traffic. The single-arm script indexed the palette by traffic rank,
      so removing one predecessor re-coloured every one below it.

  targets are named by OPCODE, not address.  Every handler moves between arms
      (MUL is 0x21600 / 0x1ffce, ADD is 0x21560 / 0x201ba / 0x2006e), so each arm
      is resolved through its own optab.

  every panel in a row is normalised to the BASELINE arm's total.  Per-panel
      normalisation makes a surviving predecessor appear to gain traffic it never
      gained: guard MUL->MUL and MUL's recorded instances fall 100.6M -> 60.6M, so
      LTI renormalises 20% -> 33%. Against a fixed denominator the guarded traffic
      instead reads as missing area, which is the result.

A guarded arrival lands on the compiler's edge stub in front of the handler's disptab
entry and falls through into it; dispatch_stats canonicalises such arrivals to the
entry they flow into, so a guarded predecessor stays in its row and its bar moves
from the mispredict mode to the floor. A predecessor that is genuinely absent from a
later arm (e.g. a control binary) keeps its legend entry so rows stay comparable.

  plot_pred_grid.py --targets MUL,ADD --out fig.pred_grid \
      "baseline=base.dispatch_hist.csv:configs/lua/lua_optab_fusebase.json" \
      "+MUL->MUL=g1.dispatch_hist.csv:configs/lua/lua_optab_mulmul.json" \
      "+MUL->ADD=g2.dispatch_hist.csv:configs/lua/lua_optab_mulmul_muladd.json"
"""
import argparse
import json
import pathlib
import sys

import matplotlib as mpl
mpl.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.patches import Patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from paper_palette import (MM, VENUES, CATEGORICAL, NEUTRAL, INK, INK2, GRID,
                           style, fit_tight, save)

def load_arm(spec):
    """'LABEL=hist.csv:optab.json' -> (label, dataframe, addr->opcode, opcode->addr)."""
    label, _, rest = spec.partition('=')
    hist, _, optab = rest.partition(':')
    if not (hist and optab):
        raise SystemExit(f'expected LABEL=hist.csv:optab.json, got {spec!r}')
    tab = {int(k, 16): v for k, v in json.load(open(optab)).items()}
    d = pd.read_csv(hist)
    for c in ('from_handler', 'to_handler'):
        d[c] = d[c].map(lambda s: int(str(s).strip(), 16))
    return label, d, tab, {v: k for k, v in tab.items()}


def contexts(d, tab, target_addr):
    """-> (total instances, {predecessor opcode: (cycles, counts)}).

    Aggregated BY OPCODE: if two addresses resolve to the same handler name they add
    up rather than the second silently replacing the first."""
    s = d[d.to_handler == target_addr]
    acc = {}
    for f, g in s.groupby('from_handler'):
        name = tab.get(f, hex(f))
        h = g.groupby('cycles')['count'].sum()
        acc[name] = acc[name].add(h, fill_value=0) if name in acc else h
    out = {name: (h.sort_index().index.to_numpy(float), h.sort_index().to_numpy(float))
           for name, h in acc.items()}
    return int(s['count'].sum()), out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('arms', nargs='+', metavar='LABEL=HIST:OPTAB',
                    help='baseline first; column order is the order given')
    ap.add_argument('--targets', required=True,
                    help='comma-separated opcode names, one row each (e.g. MUL,ADD)')
    ap.add_argument('--out', required=True)
    ap.add_argument('--venue', default='acm', choices=sorted(VENUES))
    ap.add_argument('--span', default='double', choices=('single', 'double'))
    ap.add_argument('--width', type=float)
    ap.add_argument('--row-height', type=float, default=40.0, help='mm per row')
    ap.add_argument('--min-share', type=float, default=0.01,
                    help='predecessors below this share of the baseline pool as "other"')
    ap.add_argument('--coverage', type=float, default=0.999)
    a = ap.parse_args()

    arms = [load_arm(s) for s in a.arms]
    targets = [t.strip() for t in a.targets.split(',') if t.strip()]
    st = style(venue=a.venue)
    width = a.width if a.width else st[a.span]

    # ---- gather every panel
    grid, keys, denoms, xmaxes, xlos, ranked = {}, {}, {}, {}, {}, {}
    for tgt in targets:
        for label, d, tab, rev in arms:
            if tgt not in rev:
                raise SystemExit(f'{tgt}: not a handler in the optab for arm {label!r}')
            n, ctx = contexts(d, tab, rev[tgt])
            grid[(tgt, label)] = (n, ctx)
        denoms[tgt] = grid[(tgt, arms[0][0])][0]          # the baseline arm's total
        # Rank and threshold on the BASELINE arm alone. Summing traffic across arms
        # demotes exactly the predecessor the figure is about -- one that gets guarded
        # away appears in fewer arms, so its cross-arm total is smaller than the
        # survivors' -- and it multiplies every share by the number of arms, which
        # lets sub-1% predecessors clear --min-share spuriously.
        base_ctx = grid[(tgt, arms[0][0])][1]
        share = {p: w.sum() / max(1, denoms[tgt]) for p, (_, w) in base_ctx.items()}
        ranked[tgt] = [p for p in sorted(share, key=lambda p: -share[p])
                       if share[p] >= a.min_share]

    # ---- colour key: an opcode appearing in more than one row must keep ONE colour
    # across the whole figure, so those are assigned first; each row then fills its
    # remaining slots from the unused hues, in baseline-traffic order.
    rows_of = {}
    for tgt in targets:
        for p in ranked[tgt]:
            rows_of.setdefault(p, []).append(tgt)
    shared = sorted((p for p, rs in rows_of.items() if len(rs) > 1),
                    key=lambda p: -len(rows_of[p]))
    glob, nxt = {}, 0
    for p in shared:
        if nxt < len(CATEGORICAL):
            glob[p] = CATEGORICAL[nxt]; nxt += 1
    for tgt in targets:
        key, used = {}, set(glob.values())
        for p in ranked[tgt]:
            if p in glob:
                key[p] = glob[p]
            else:
                free = [c for c in CATEGORICAL if c not in used and c not in key.values()]
                if free:
                    key[p] = free[0]; used.add(free[0])
        keys[tgt] = key
        # one x range per row so the columns are directly comparable
        allc = np.concatenate([c for _, ctx in
                               (grid[(tgt, l)] for l, *_ in arms) for c, _ in ctx.values()])
        allw = np.concatenate([w for _, ctx in
                               (grid[(tgt, l)] for l, *_ in arms) for _, w in ctx.values()])
        o = np.argsort(allc)
        cdf = np.cumsum(allw[o]) / allw.sum()
        xmaxes[tgt] = int(allc[o][np.searchsorted(cdf, a.coverage)]) + 2
        # Start the axis ON the 0 tick, so the y spine sits at 0 rather than half a
        # bin to its left. Only drop back to -0.5 if a bar actually occupies cycle 0,
        # which would otherwise be clipped in half.
        xlos[tgt] = -0.5 if allc.min() < 1 else 0.0

    nr, nc = len(targets), len(arms)
    mpl.rcParams.update({'figure.constrained_layout.use': True,
                         'figure.constrained_layout.hspace': 0.10,
                         'figure.constrained_layout.wspace': 0.05,
                         'figure.constrained_layout.h_pad': 0.02,
                         'figure.constrained_layout.w_pad': 0.02})
    fig, axes = plt.subplots(nr, nc, figsize=(width * MM, nr * a.row_height * MM),
                             squeeze=False)
    for r, tgt in enumerate(targets):
        key, denom, xmax, xlo = keys[tgt], denoms[tgt], xmaxes[tgt], xlos[tgt]
        edges = np.arange(0, xmax + 2)
        for c, (label, d, tab, rev) in enumerate(arms):
            ax = axes[r][c]
            n, ctx = grid[(tgt, label)]
            # stack in the colour key's order so the bars are also in a stable order
            order = list(key) + [p for p in ctx if p not in key]
            bottom = np.zeros(xmax + 1)
            for pred in order:
                if pred not in ctx:
                    continue
                cyc, w = ctx[pred]
                y = np.zeros(xmax + 1)
                m = cyc <= xmax
                np.add.at(y, cyc[m].astype(int), w[m])
                # centre-aligned: bar for cycle c spans [c-0.5, c+0.5), so a tick at
                # c lands in the MIDDLE of its bar. With align='edge' every tick sat on
                # the bar's left edge, half a bin off from the value it labelled.
                ax.bar(np.arange(xmax + 1), 100 * y / denom, bottom=bottom, width=1.0,
                       color=key.get(pred, NEUTRAL), edgecolor='white',
                       linewidth=0.2, zorder=3)
                bottom += 100 * y / denom
            ax.set_xlim(xlo, xmax + 0.5)
            # majors every 5 carry the label and a gridline; minors every 1 are bare
            # ticks, so a reader can count single cycles without label clutter
            ax.set_xticks(np.arange(0, xmax + 1, 5))
            ax.set_xticks(np.arange(0, xmax + 1), minor=True)
            ax.tick_params(axis='x', which='minor', length=1.3, width=0.4)
            ax.xaxis.grid(True, which='major', color=GRID, linewidth=st['grid_lw'])
            ax.set_ylim(0, 100 * max(1.0, 1.02) * 0.0 + _rowmax(grid, tgt, arms, denom, xmax) * 1.18)
            ax.spines[['top', 'right']].set_visible(False)
            ax.set_axisbelow(True)
            ax.yaxis.grid(True, color=GRID, linewidth=st['grid_lw'])
            if r == 0:
                ax.set_title(label, loc='center', color=INK, pad=3)
            if c == 0:
                ax.set_ylabel(f'{tgt} entry BB\n(% of baseline instances)')
            if r == nr - 1:
                ax.set_xlabel('Entry BB latency (cycles)')
            else:
                ax.tick_params(labelbottom=False)
            ax.text(0.97, 0.94, f'{n/1e6:.1f}M instances', transform=ax.transAxes,
                    ha='right', va='top', fontsize=st['tick'], color=INK2,
                    bbox=dict(facecolor='white', edgecolor='none', pad=0.6))
            ax.text(-0.03, 1.10, 'abcdefghi'[r * nc + c], transform=ax.transAxes,
                    fontsize=st['panel'], fontweight='bold', va='top', ha='left')

        # one legend per row, since the colour key is per row
        h = []
        for pred, col in key.items():
            h.append(Patch(facecolor=col, edgecolor='white', linewidth=0.3,
                           label=f'after {pred}'))
        if any(p not in key for arm in arms for p in grid[(tgt, arm[0])][1]):
            h.append(Patch(facecolor=NEUTRAL, edgecolor='white', linewidth=0.3,
                           label='other'))
        axes[r][-1].legend(handles=h, loc='upper right', bbox_to_anchor=(1.0, 0.86),
                           frameon=False, handlelength=1.2, handletextpad=0.4,
                           labelspacing=0.3)

    got_w, got_h = fit_tight(fig, width, nr * a.row_height)
    save(fig, a.out)
    plt.close(fig)

    for tgt in targets:
        print(f'\n{tgt} entry block   (denominator: {denoms[tgt]:,} baseline instances)')
        print(f"  {'predecessor':>12} " + ' '.join(f'{l:>16}' for l, *_ in arms))
        preds = list(keys[tgt]) + sorted({p for l, *_ in arms
                                          for p in grid[(tgt, l)][1] if p not in keys[tgt]})
        for pred in preds:
            cells = []
            for label, *_ in arms:
                ctx = grid[(tgt, label)][1]
                if pred in ctx:
                    cyc, w = ctx[pred]
                    cells.append(f'{w.sum()/1e6:6.1f}M @{(cyc*w).sum()/w.sum():5.2f}')
                else:
                    cells.append(f'{"absent":>16}')
            print(f'  {pred:>12} ' + ' '.join(f'{c:>16}' for c in cells))
    print(f'\nwrote {a.out}.pdf and {a.out}.png — {nr}x{nc} panels, '
          f'{got_w:.1f}x{got_h:.1f} mm, {st["base"]:.0f} pt ({a.venue})')


def _rowmax(grid, tgt, arms, denom, xmax):
    """Tallest stacked bar anywhere in the row, as a share of the fixed denominator."""
    best = 0.0
    for label, *_ in arms:
        _, ctx = grid[(tgt, label)]
        y = np.zeros(xmax + 1)
        for cyc, w in ctx.values():
            m = cyc <= xmax
            np.add.at(y, cyc[m].astype(int), w[m])
        best = max(best, 100 * y.max() / denom)
    return best


if __name__ == '__main__':
    main()
