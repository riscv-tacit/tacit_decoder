#!/usr/bin/env python3
"""Latency histogram of the same basic block under two builds, side by side.

For an A/B whose two binaries share addresses (e.g. lua-fuse-mulmul vs
lua-mulmul-gt127, which differ in one immediate), a block pairs exactly, so the
two distributions are directly comparable with no address mapping and no
fingerprinting. Grouped bars rather than overlaid curves: the support is a
handful of integer cycle counts, and what matters is which bin the mass sits in.

  plot_block_ab.py --a base.bb_hist.csv --a-label "guard off" \
      --b fused.bb_hist.csv --b-label "guard on" \
      --block 0x2003c-0x2004c=B7 fmul --out fig.b7
"""
import argparse
import pathlib
import sys

import matplotlib as mpl
mpl.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from paper_palette import MM, SINGLE_COL, NAVY, CORAL, INK, INK2, GRID, style, fit_tight, save


def hist(path, bb):
    d = pd.read_csv(path)
    d['bb'] = d['bb'].astype(str).str.strip()
    s = d[d.bb == bb]
    if s.empty:
        return None
    return s.set_index('cycles')['count'].sort_index()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--a', required=True, help='bb_hist CSV for arm A')
    ap.add_argument('--b', required=True, help='bb_hist CSV for arm B')
    ap.add_argument('--a-label', default='A')
    ap.add_argument('--b-label', default='B')
    ap.add_argument('--block', action='append', required=True, metavar='ADDR=TITLE',
                    help='block to plot, one panel each; repeatable')
    ap.add_argument('--out', required=True)
    ap.add_argument('--width', type=float, default=SINGLE_COL)
    ap.add_argument('--panel-height', type=float, default=32.0, help='mm per panel')
    a = ap.parse_args()

    panels = []
    for spec in a.block:
        bb, _, title = spec.partition('=')
        ha, hb = hist(a.a, bb), hist(a.b, bb)
        if ha is None or hb is None:
            raise SystemExit(f'{bb} missing from '
                             f'{"A" if ha is None else "B"}; raise hist_top and re-decode')
        panels.append((bb, title or bb, ha, hb))

    style()
    n = len(panels)
    fig, axes = plt.subplots(n, 1, figsize=(a.width * MM, n * a.panel_height * MM))
    axes = np.atleast_1d(axes)
    lines = []
    for k, (ax, (bb, title, ha, hb)) in enumerate(zip(axes, panels)):
        na, nb = ha.sum(), hb.sum()
        # keep every bin holding >=0.2% in either arm; the rest is a long thin tail
        cyc = sorted(set(ha[ha / na >= 0.002].index) | set(hb[hb / nb >= 0.002].index))
        pa = [100 * ha.get(c, 0) / na for c in cyc]
        pb = [100 * hb.get(c, 0) / nb for c in cyc]
        x = np.arange(len(cyc))
        ax.bar(x - 0.21, pa, width=0.40, color=NAVY, edgecolor='white', linewidth=0.3,
               label=a.a_label, zorder=3)
        ax.bar(x + 0.21, pb, width=0.40, color=CORAL, edgecolor='white', linewidth=0.3,
               label=a.b_label, zorder=3)
        ax.set_xticks(x); ax.set_xticklabels([str(c) for c in cyc])
        ax.set_xlim(-0.6, len(cyc) - 0.4)
        ax.set_ylim(0, max(max(pa), max(pb)) * 1.16)
        ax.set_ylabel('Share of executions (%)')
        if k == n - 1:      # only the bottom panel; otherwise it lands on the next title
            ax.set_xlabel('Block latency (cycles)')
        ax.spines[['top', 'right']].set_visible(False)
        ax.set_axisbelow(True)
        ax.yaxis.grid(True, color=GRID, linewidth=0.3)
        ax.set_title(f'{title}   {bb}', loc='left', color=INK, pad=2)
        ax.text(0.985, 0.95, f"mean {(ha.index*ha).sum()/na:.2f} → "
                             f"{(hb.index*hb).sum()/nb:.2f} cyc",
                transform=ax.transAxes, ha='right', va='top', fontsize=5, color=INK2)
        ax.text(-0.155, 1.10, 'abcdefgh'[k], transform=ax.transAxes,
                fontsize=8, fontweight='bold', va='top', ha='left')
        lines.append(f'{title} {bb}: n={int(na):,}/{int(nb):,}  '
                     f'mean {(ha.index*ha).sum()/na:.3f} -> {(hb.index*hb).sum()/nb:.3f}')

    # one legend for the figure, below everything: inside a panel it collides with
    # either the title or the mean annotation
    h, l = axes[0].get_legend_handles_labels()
    fig.legend(h, l, loc='lower center', ncol=2, bbox_to_anchor=(0.5, -0.02),
               handlelength=1.1, handletextpad=0.4, columnspacing=1.6)
    fig.subplots_adjust(hspace=0.55)
    got_w, got_h = fit_tight(fig, a.width, n * a.panel_height)
    save(fig, a.out)
    plt.close(fig)
    print('\n'.join(lines))
    print(f'wrote {a.out}.pdf and {a.out}.png — {n} panels, {got_w:.1f}x{got_h:.1f} mm')


if __name__ == '__main__':
    main()
