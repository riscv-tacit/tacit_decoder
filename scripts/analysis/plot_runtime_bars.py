#!/usr/bin/env python3
"""Runtime before and after each fusion step, straight from the guests' uartlogs.

The deliberately boring figure: one bar per interpreter arm, absolute cycles,
y from zero. Reads `window_cycles~=` (the traced region, which is what the
analysis is scoped to) and the `*** PASSED *** after N cycles` line, plus the
program's own output so a wrong answer cannot masquerade as a speedup.

Arms are an ORDERED family -- baseline, +guard, +guard+guard -- so they get
tints of one hue, light to dark, never separate colours.

  plot_runtime_bars.py --out fig.runtime \
      "baseline=bundles/lua-fuse-base-mandelbrot-20260901" \
      "+MUL->MUL=bundles/lua-fuse-mulmul-mandelbrot-20260903" \
      "+MUL->ADD=bundles/lua-fuse-mmadd-mandelbrot-20260903"
"""
import argparse
import pathlib
import re
import sys

import matplotlib as mpl
mpl.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from paper_palette import (MM, VENUES, CORAL, INK, INK2, GRID,
                           ordered, luminance, style, fit_tight, save)


def read_uartlog(path):
    """Accept a uartlog, a bundle dir, or a FireSim job dir."""
    p = pathlib.Path(path)
    for cand in (p, p / 'uartlog', *sorted(p.glob('*/uartlog'))):
        if cand.is_file():
            t = cand.read_bytes().decode('utf8', 'replace')      # guest logs carry \r
            grab = lambda pat: (lambda m: m.group(1) if m else None)(re.search(pat, t))
            win = grab(r'window_cycles~=(\d+)')
            tot = grab(r'PASSED \*\*\* after (\d+) cycles')
            if win or tot:
                return dict(path=cand, window=int(win) if win else None,
                            total=int(tot) if tot else None,
                            stall=int(grab(r'stall_cycles=(\d+)') or 0),
                            out=(grab(r'(inset \d+ checksum \d+)')
                                 or grab(r'^([0-9]+\.[0-9]+)\s*$') or '?'))
    raise SystemExit(f'{path}: no uartlog with a window_cycles or PASSED line')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('arms', nargs='+', metavar='LABEL=PATH',
                    help='baseline first; order is the order plotted')
    ap.add_argument('--out', required=True)
    ap.add_argument('--metric', choices=('window', 'total'), default='window',
                    help='window: the traced region (default). total: whole simulation, '
                         'which includes boot and so dilutes the effect.')
    ap.add_argument('--venue', default='acm', choices=sorted(VENUES),
                    help='sizes text to that venue: acm = 8 pt labels, 7 pt ticks, '
                         '84.8/177.8 mm columns (default)')
    ap.add_argument('--span', default='single', choices=('single', 'double'),
                    help='single column (default); three bars do not need the span')
    ap.add_argument('--width', type=float, help='mm, overrides --venue/--span')
    ap.add_argument('--height', type=float, default=55.0)
    ap.add_argument('--font-scale', type=float, default=1.0)
    a = ap.parse_args()

    labels, data = [], []
    for spec in a.arms:
        if '=' not in spec:
            raise SystemExit(f'expected LABEL=PATH, got {spec!r}')
        lab, path = spec.split('=', 1)
        labels.append(lab)
        data.append(read_uartlog(path))
    cyc = [d[a.metric] for d in data]
    if any(c is None for c in cyc):
        raise SystemExit(f'some arms have no {a.metric} cycle count')
    base = cyc[0]

    st = style(venue=a.venue, scale=a.font_scale)
    width = a.width if a.width else st[a.span]
    fig, ax = plt.subplots(figsize=(width * MM, a.height * MM))
    # light -> dark as guards accumulate: the baseline is the palest, the most
    # heavily fused arm the most saturated. Taken from the dark end of the ramp so
    # every bar can carry white text if it needs to.
    cols = ordered(len(cyc) + 1)[:len(cyc)][::-1]
    x = np.arange(len(cyc))
    top = max(cyc) / 1e9
    ax.bar(x, [c / 1e9 for c in cyc], width=0.46, color=cols,
           edgecolor='white', linewidth=0.4, zorder=3)

    # Absolute value INSIDE the bar, which leaves the space above it free for the
    # drop arrow to sit directly over its own bar. No unit here: it is in the y
    # label, and saying it twice is noise. Ink follows the bar's luminance.
    for xi, c in zip(x, cyc):
        ax.text(xi, c / 1e9 - top * 0.03, f'{c/1e9:.2f}', ha='center', va='top',
                fontsize=st['base'], zorder=5,
                color='white' if luminance(cols[xi]) < 0.35 else INK)

    # The deltas are the claim, so they take the accent colour and drop from a
    # dashed baseline reference straight down onto their own bar.
    ax.axhline(base / 1e9, xmin=0.02, xmax=0.98, color=INK2, lw=0.5,
               ls=(0, (3, 2)), zorder=2)
    for xi, c in list(zip(x, cyc))[1:]:
        ax.annotate('', xy=(xi, c / 1e9), xytext=(xi, base / 1e9),
                    arrowprops=dict(arrowstyle='-|>,head_width=0.11,head_length=0.30',
                                    color=CORAL, lw=0.8, shrinkA=0, shrinkB=0), zorder=6)
        ax.text(xi + 0.07, (c / 1e9 + base / 1e9) / 2, f'{100*(c-base)/base:+.1f}%',
                ha='left', va='center', fontsize=st['base'], color=CORAL, zorder=6)

    ax.set_xticks(x); ax.set_xticklabels(labels)
    ax.set_xlim(-0.5, len(cyc) - 0.5)
    ax.set_ylim(0, top * 1.14)
    ax.set_ylabel('Cycles (10⁹)' + ('' if a.metric == 'window' else ', whole simulation'))
    ax.set_axisbelow(True)
    ax.yaxis.grid(True, color=GRID, linewidth=st['grid_lw'])
    ax.spines[['top', 'right']].set_visible(False)

    got_w, got_h = fit_tight(fig, width, a.height)
    save(fig, a.out)
    plt.close(fig)

    w = max(len(l) for l in labels)
    print(f"  {'arm':{w}} {'window':>15} {'total':>15} {'vs base':>9}  output")
    for l, d in zip(labels, data):
        rel = 100 * (d[a.metric] - base) / base
        print(f'  {l:{w}} {d["window"] or 0:15,} {d["total"] or 0:15,} '
              f'{rel:+8.2f}%  {d["out"]}')
    outs = {d['out'] for d in data}
    print(f'\n  program output identical across arms: '
          f'{"YES" if len(outs) == 1 else "NO -- " + repr(outs)}')
    print(f'  max trace-unit stall: {max(d["stall"] for d in data)} cycles')
    print(f'\nwrote {a.out}.pdf and {a.out}.png — {got_w:.1f}x{got_h:.1f} mm at final size, '
          f"{st['base']:.1f} pt labels / {st['tick']:.1f} pt ticks ({a.venue})")


if __name__ == '__main__':
    main()
