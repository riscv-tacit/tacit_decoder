#!/usr/bin/env python3
"""Per-predecessor latency distributions for a handler's entry block.

The vbb ranking says which blocks vary; it cannot say why. Conditioning each
block's latency on the handler that ran immediately before it shows the shape of
the answer: a block whose aggregate distribution looks broad is usually a mixture
of per-predecessor modes, each much tighter than the whole.

What that does NOT settle is whether a dispatch guard would help. The guard is
installed at the *predecessor's* dispatch site and its payoff depends on that
site's successor spread, so a target-centric view like this one splits a single
site's behaviour across several panels. Deciding guard value needs the
source-centric view, and ultimately a built variant and a re-measurement.

Reads the dispatch_stats receiver's hist_path dump (from_handler, to_handler,
cycles, count), which is the entry-block latency of to_handler conditioned on the
previous handler entered, so the sum over predecessors reproduces that block's
bb_stats histogram exactly.

  plot_pred_distributions.py --hist trace.mandelbrot.dispatch_hist.csv \
      --optab configs/lua/lua_optab_fusebase.json --targets MUL,ADD \
      --bb-stats trace.mandelbrot.bb_stats.csv --out output_mandelbrot/fig.pred
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

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from paper_palette import (MM, SINGLE_COL, CATEGORICAL, CATEGORICAL_DASH, NEUTRAL,
                           INK, INK2, GRID, style, fit_tight, save)


def quantile(cyc, w, p):
    """p-quantile of a histogram given as sorted (value, weight) arrays."""
    return int(cyc[np.searchsorted(np.cumsum(w) / w.sum(), p)])


def contexts(hist, target, min_share, max_hues):
    """-> (global p5, total n, display contexts, vbb total) for one block.

    The total is sum_k n_k*(mean_k - p5_global), which is the block's vbb and is
    invariant to how the contexts are pooled for drawing -- means are additive by
    weight and the floor is common to all of them. It is reported only as a
    cross-check against bb_stats.
    """
    s = hist[hist.to_handler == target]
    if s.empty:
        raise SystemExit(f'no dispatches into 0x{target:x} in the histogram')
    n_tot = int(s['count'].sum())
    agg = s.groupby('cycles')['count'].sum().sort_index()
    p5g = quantile(agg.index.to_numpy(), agg.to_numpy(), 0.05)

    every = []
    for f, g in s.groupby('from_handler'):
        g = g.sort_values('cycles')
        cyc, w = g['cycles'].to_numpy(), g['count'].to_numpy()
        n = int(w.sum())
        every.append(dict(pred=f, n=n, share=n / n_tot, cyc=cyc, w=w,
                          mean=float((cyc * w).sum() / n), p5=quantile(cyc, w, 0.05),
                          p50=quantile(cyc, w, 0.50), p90=quantile(cyc, w, 0.90),
                          p99=quantile(cyc, w, 0.99)))
    vbb_total = sum(c['n'] * (c['mean'] - p5g) for c in every)

    every.sort(key=lambda c: -c['n'])
    keep = [c for c in every if c['share'] >= min_share][:max_hues]
    rest = [c for c in every if c not in keep]

    # A predecessor set wider than the palette is itself the finding -- nothing
    # modal to peel -- so the tail pools into the neutral rather than taking a
    # hue that stops carrying an argument and starts being decoration.
    if rest:
        allc = np.concatenate([c['cyc'] for c in rest])
        allw = np.concatenate([c['w'] for c in rest])
        cyc, inv = np.unique(allc, return_inverse=True)
        w = np.zeros(len(cyc), dtype=np.int64)
        np.add.at(w, inv, allw)
        n = int(w.sum())
        keep = keep + [dict(pred=None, n=n, share=n / n_tot, cyc=cyc, w=w,
                            mean=float((cyc * w).sum() / n),
                            p5=quantile(cyc, w, 0.05), p50=quantile(cyc, w, 0.50),
                            p90=quantile(cyc, w, 0.90), p99=quantile(cyc, w, 0.99),
                            n_preds=len(rest))]
    return p5g, n_tot, keep, vbb_total


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--hist', required=True, help='dispatch_stats hist_path CSV')
    ap.add_argument('--optab', required=True, help='handler address -> opcode name')
    ap.add_argument('--targets', required=True,
                    help='comma-separated opcode names or hex addresses, one panel '
                         'each; or "top:N" to take the N handler entry blocks with '
                         'the largest vbb (requires --bb-stats)')
    ap.add_argument('--bb-stats', help='cross-check each panel total against bb_stats vbb')
    ap.add_argument('--out', required=True, help='prefix: writes <out>.{pdf,png,txt}')
    ap.add_argument('--min-share', type=float, default=0.01,
                    help='predecessors below this share are pooled as "other"')
    ap.add_argument('--max-hues', type=int, default=len(CATEGORICAL),
                    help='predecessors resolved by colour; the rest pool into the '
                         'neutral (the decomposition is unaffected either way)')
    ap.add_argument('--style', choices=('stacked', 'overlay'), default='stacked',
                    help='stacked: one bar per cycle, split by predecessor, so the '
                         'bar total is the block\'s own latency histogram (default). '
                         'overlay: one normalised curve per predecessor')
    ap.add_argument('--coverage', type=float, default=0.999,
                    help='x range covers this fraction of every panel\'s instances')
    ap.add_argument('--width', type=float, default=SINGLE_COL)
    ap.add_argument('--height', type=float, default=68.0)
    a = ap.parse_args()

    optab = {int(k, 16): v for k, v in json.load(open(a.optab)).items()}
    rev = {v: k for k, v in optab.items()}
    hist = pd.read_csv(a.hist)
    for c in ('from_handler', 'to_handler'):
        hist[c] = hist[c].map(lambda s: int(str(s).strip(), 16))

    bb = None
    if a.bb_stats:
        bb = pd.read_csv(a.bb_stats, skipinitialspace=True)
        bb['bb'] = bb['bb'].str.strip()
        bb['addr'] = bb['bb'].str.split('-').str[0].map(
            lambda h: -1 if h.startswith('0xffffffff') else int(h, 16))

    if a.targets.strip().lower().startswith('top:'):
        if bb is None:
            raise SystemExit('--targets top:N needs --bb-stats to rank on')
        n = int(a.targets.split(':', 1)[1])
        seen = set(hist.to_handler)
        cand = bb[bb['addr'].isin(set(optab) & seen)].sort_values('vbb', ascending=False)
        targets = [(int(r.addr), optab[int(r.addr)]) for r in cand.head(n).itertuples()]
        if not targets:
            raise SystemExit('no handler entry block appears in both the histogram '
                             'and the bb_stats CSV')
    else:
        targets = []
        for t in a.targets.split(','):
            t = t.strip()
            addr = int(t, 16) if t.lower().startswith('0x') else rev.get(t)
            if addr is None:
                raise SystemExit(f'{t!r} is not a handler name in {a.optab}')
            targets.append((addr, optab.get(addr, t)))

    panels = [(addr, name) + contexts(hist, addr, a.min_share, a.max_hues)
              for addr, name in targets]

    # Cross-check against bb_stats. A handler's arrivals live in every block that STARTS at
    # its entry or FALLS THROUGH into it (a guard's edge stub in front of the entry), so sum
    # over those blocks, and use the panel's global p5 so both sides measure the same thing:
    # sum_blocks n_b * (mean_b - p5_global).
    vbb_ref, rank_ref, nblk_ref = {}, {}, {}
    if bb is not None:
        bb['end'] = bb['bb'].str.split('-').str[1].map(
            lambda h: -1 if h.startswith('0xffffffff') else int(h, 16))
        order = bb.sort_values('vbb', ascending=False).reset_index(drop=True)
        for addr, name, p5g, *_ in panels:
            m = order[(order['addr'] == addr) | ((order['addr'] < addr) & (addr <= order['end']))]
            if not m.empty:
                vbb_ref[addr] = float((m['count'] * (m['mean'] - p5g)).sum())
                nblk_ref[addr] = len(m)
                rank_ref[addr] = int(m.index.min()) + 1

    # One x range for every panel: the claim is that the contexts sit at different
    # latencies, which is only legible if the axes are directly comparable.
    xmax = 0
    for *_, ctxs, _tot in panels:
        allc = np.concatenate([c['cyc'] for c in ctxs])
        allw = np.concatenate([c['w'] for c in ctxs])
        o = np.argsort(allc)
        xmax = max(xmax, quantile(allc[o], allw[o], a.coverage))
    xmax = int(xmax) + 2

    style()
    fig, axes = plt.subplots(len(panels), 1, figsize=(a.width * MM, a.height * MM),
                             sharex=True)
    axes = np.atleast_1d(axes)
    edges = np.arange(0, xmax + 2)
    clipped_note = []

    for k, (ax, (addr, name, p5g, n_tot, ctxs, _tot)) in \
            enumerate(zip(axes, panels)):
        shown = 0
        bottom = np.zeros(xmax + 1)
        for i, c in enumerate(ctxs):
            col, dash = (NEUTRAL, (0, (1, 1))) if c['pred'] is None else \
                (CATEGORICAL[i], CATEGORICAL_DASH[i])
            y = np.zeros(xmax + 1)
            keep = c['cyc'] <= xmax
            np.add.at(y, c['cyc'][keep], c['w'][keep])
            shown += c['w'][keep].sum()
            lbl = (f"other, {c['n_preds']} pred{'s' if c['n_preds'] > 1 else ''}"
                   f" ({100 * c['share']:.1f}%)"
                   if c['pred'] is None
                   else f"after {optab.get(c['pred'], hex(c['pred']))} "
                        f"({100 * c['share']:.1f}%)")
            if a.style == 'stacked':
                # Bars tile the axis at the histogram's own 1-cycle resolution, so
                # the stack total is the block's real latency distribution and each
                # mode is visibly owned by whichever predecessor supplies it.
                # centre-aligned so a tick at cycle c sits in the middle of bar c
                ax.bar(np.arange(xmax + 1), 100 * y / n_tot, bottom=bottom, width=1.0,
                       color=col, edgecolor='white', linewidth=0.2,
                       label=lbl, zorder=3)
                bottom += 100 * y / n_tot
            else:
                # Contexts can be exactly coincident -- two predecessors that both
                # land the block in 4 cycles is a finding, not a collision to jitter
                # away -- so later curves draw thinner and on top, leaving the
                # earlier one as a visible halo instead of being hidden by it.
                ax.stairs(y / c['n'], edges, color=col, linewidth=1.3 - 0.13 * i,
                          linestyle=dash, baseline=None, label=lbl,
                          zorder=3 + 0.1 * i)
                ax.stairs(y / c['n'], edges, color=col, fill=True, alpha=0.07,
                          baseline=0, linewidth=0, zorder=2)
        frac = 100 * (1 - shown / n_tot)
        if frac > 0.05:
            clipped_note.append(f'{name}: {frac:.2f}% of instances beyond {xmax} cyc')

        if a.style == 'stacked':
            ax.set_ylim(0, bottom.max() * 1.22)
            ax.set_ylabel('Share of dispatches (%)')
        else:
            ax.set_ylim(0, 1.0)
            ax.set_yticks([0, 0.5, 1.0])
            ax.set_ylabel('Share of instances')
        # start on the 0 tick unless a bar occupies cycle 0
        ax.set_xlim(-0.5 if any(c['cyc'].min() < 1 for c in ctxs) else 0.0,
                    xmax + 0.5)
        ax.set_xticks(np.arange(0, xmax + 1, 5))
        ax.set_xticks(np.arange(0, xmax + 1), minor=True)
        ax.spines[['top', 'right']].set_visible(False)
        ax.set_axisbelow(True)
        ax.yaxis.grid(True, color=GRID, linewidth=0.3)
        rk = f'  (vbb rank {rank_ref[addr]})' if addr in rank_ref else ''
        ax.set_title(f'{name} entry block, 0x{addr:x}{rk}', loc='left', color=INK, pad=2)
        ax.legend(loc='best', handlelength=1.4 if a.style == 'stacked' else 1.8,
                  handletextpad=0.45, labelspacing=0.28, borderpad=0.3).set_zorder(6)
        ax.text(-0.115, 1.06, 'abcdefgh'[k], transform=ax.transAxes,
                fontsize=8, fontweight='bold', va='top', ha='left')

    axes[-1].set_xlabel('Entry-block latency (cycles)')

    got_w, got_h = fit_tight(fig, a.width, a.height)
    save(fig, a.out)
    plt.close(fig)

    lines = ['=' * 78,
             'Entry-block latency by predecessor  ' + f'({a.hist})',
             '=' * 78]
    for addr, name, p5g, n_tot, ctxs, vbb_total in panels:
        lines += ['', f'-- {name} 0x{addr:x} ' + '-' * (60 - len(name)),
                  f'  {n_tot:,} dispatches, {len(ctxs)} contexts, global p5 = {p5g} cyc',
                  f"  {'predecessor':>16} {'instances':>13} {'share':>7} {'p5':>4} "
                  f"{'p50':>4} {'p90':>4} {'p99':>4} {'mean':>7} {'excess Mcyc':>12}"]
        for c in ctxs:
            nm = 'other (pooled)' if c['pred'] is None else \
                optab.get(c['pred'], hex(c['pred']))
            lines.append(f"  {nm:>16} {c['n']:13,d} {100 * c['share']:6.1f}% "
                         f"{c['p5']:4d} {c['p50']:4d} {c['p90']:4d} {c['p99']:4d} "
                         f"{c['mean']:7.2f} "
                         f"{c['n'] * (c['mean'] - p5g) / 1e6:11.1f}M")
        lines.append(f'  excess over the global p5 floor, summed: '
                     f'{vbb_total / 1e6:.1f} Mcyc' +
                     (f'   (bb_stats, same floor, over {nblk_ref[addr]} block'
                      f'{"s" if nblk_ref[addr] != 1 else ""}: {vbb_ref[addr] / 1e6:.1f} Mcyc)'
                      if addr in vbb_ref else ''))
    if clipped_note:
        lines += ['', 'x range clipped: ' + '; '.join(clipped_note)]
    txt = '\n'.join(lines) + '\n'
    open(f'{a.out}.txt', 'w').write(txt)
    print(txt)
    print(f'wrote {a.out}.pdf, {a.out}.png and {a.out}.txt — {len(panels)} panels, '
          f'{got_w:.1f}x{got_h:.1f} mm at final size')


if __name__ == '__main__':
    main()
