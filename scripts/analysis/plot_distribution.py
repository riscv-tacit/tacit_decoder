# Given a sequence of "iter: time_ns" lines, plot the distribution of the times.
# Renders at single-column (89 mm) paper size; no title, the caption carries it.

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import argparse
import re

pattern = r'(\d+): (\d+)'
INK, INK2, GRID = "#1a1a19", "#5f5e56", "#e6e5df"
BAR = "#2a78d6"
MM = 1 / 25.4
SINGLE_COL = 89 * MM

matplotlib.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["Arial", "Helvetica", "DejaVu Sans"],
    "font.size": 8,
    "axes.labelsize": 8,
    "xtick.labelsize": 7,
    "ytick.labelsize": 7,
    "legend.fontsize": 7,
    "axes.linewidth": 0.6,
    "xtick.major.width": 0.5, "ytick.major.width": 0.5,
    "xtick.major.size": 2.5, "ytick.major.size": 2.5,
    "pdf.fonttype": 42, "ps.fonttype": 42,
    "savefig.dpi": 300,
})

# One series here, so colour is free to encode the percentile (in the density
# figure colour encodes the series instead). Okabe-Ito hues, colourblind-safe;
# p50 falls inside the blue body of the histogram, so it takes near-black rather
# than a hue, which would not carry over the bars;
# the dash styles are kept as a redundant encoding so the figure also survives
# greyscale printing, and they match plot_tracepoint_overhead_density.py.
STYLES = [("p50", 50, (0, (2, 2)), "#1a1a19"),
          ("p90", 90, (0, (4, 1, 1, 1)), "#E69F00"),
          ("p99", 99, "solid", "#CC79A7"),
          ("p99.9", 99.9, (0, (6, 1)), "#D55E00")]


def plot_distribution(input_file: str, out: str = None, bin_us: float = 5.0,
                      xlim: tuple = None) -> None:
    with open(input_file, 'rb') as f:
        content = f.read().decode('utf-8', 'replace')
    times = np.array([int(m[1]) for m in re.findall(pattern, content)],
                     dtype=float) / 1000.0  # ns -> us

    fig, ax = plt.subplots(figsize=(SINGLE_COL, SINGLE_COL * 0.46),
                           layout="constrained")
    lo, hi = (xlim if xlim else (times.min() - bin_us, times.max() + bin_us))
    bins = np.arange(lo, hi + bin_us, bin_us)
    counts, _, _ = ax.hist(times, bins=bins,
                           weights=np.full(len(times), 100.0 / len(times)),
                           color=BAR, alpha=0.85, linewidth=0)
    ytop = counts.max() * 1.20

    stats = {}
    for name, q, ls, colour in STYLES:
        v = np.median(times) if q == 50 else np.percentile(times, q)
        stats[name] = v
        ax.axvline(v, color=colour, linestyle=ls, linewidth=0.9, label=name)
        # value annotated beside the line (not centred on it, which would strike
        # the digits through); flipped to the left near the right edge
        right = (v - lo) / (hi - lo) < 0.70
        ax.text(v + (8 if right else -8), counts.max() * 1.02, f'{v:.0f}',
                color=colour, fontsize=7, va='bottom',
                ha='left' if right else 'right')

    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(GRID)
    ax.tick_params(colors=INK2)
    ax.grid(axis="y", color=GRID, linewidth=0.3)
    ax.set_axisbelow(True)
    ax.set_xlim(lo, hi)
    ax.set_ylim(0, ytop)
    ax.set_xlabel('Process launch latency (µs)', color=INK2)
    ax.set_ylabel('Launches (%)', color=INK2)
    ax.legend(frameon=False, labelcolor='linecolor', handlelength=1.8, labelspacing=0.2,
              borderpad=0.0, handletextpad=0.5, loc='upper right')

    print(f'{input_file}: {times.min():.0f} to {times.max():.0f} us, '
          f'n = {len(times)}, {bin_us:g} us bins')
    print(f'{input_file}: {times.mean():.1f} mean')
    for name, q, _, _c in STYLES:
        print(f'{input_file}: {stats[name]:.1f} {name}')

    fig.savefig(out or f'{input_file}.png')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', type=str, required=True)
    parser.add_argument('--out', type=str, default=None,
                        help='output image path (default: <input>.png)')
    parser.add_argument('--bin-us', type=float, default=5.0,
                        help='histogram bin width in us (default 5)')
    parser.add_argument('--xlim', type=float, nargs=2, default=None,
                        metavar=('LO', 'HI'), help='x range in us')
    args = parser.parse_args()
    plot_distribution(args.input, args.out, args.bin_us,
                      tuple(args.xlim) if args.xlim else None)
