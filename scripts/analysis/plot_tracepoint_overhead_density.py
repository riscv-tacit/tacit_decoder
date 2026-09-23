#!/usr/bin/env python3
"""Paper figure: smoothed process-lifecycle latency densities, uninstrumented
control vs. the same benchmark with diagnosis tracepoints enabled (full set,
and lite = full minus rcu_invoke_callback).

Reads the per-iteration latency lines ("N: <ns>") from the three uartlogs of
the tracepoint A/B FireSim run and renders a single-column (89 mm) figure.
No title: the caption carries it in the paper.

Usage:
  plot_tracepoint_overhead_density.py [--results DIR] [--out PNG|PDF]
"""
import argparse
import re
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

DEF_RESULTS = ("/home/ubuntu/work/f2-chipyard/sims/firesim/deploy/"
               "results-workload/2026-09-06--21-38-19-process-launch-f2")
INK, INK2, GRID = "#1a1a19", "#5f5e56", "#e6e5df"
# slot directory names under --results (F2 process-launch-f2 workload); override with --slots
SERIES = [
    ("control", "process-launch-f2-collect-10k", "#2a78d6"),
    ("tracepoints, lite", "process-launch-f2-tp-lite", "#1baf7a"),
    ("tracepoints, full", "process-launch-f2-tp-full", "#eda100"),
]
XMIN, XMAX = 680, 1600
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


def load(path):
    raw = open(path, "rb").read().decode("utf-8", "replace")
    return np.array([int(m) for m in re.findall(r"^\d+: (\d+)\r*$", raw, re.M)]) / 1000.0


def smooth_pct(x, grid, sigma_us=6.0, per_us=25.0):
    step = grid[1] - grid[0]
    hist, _ = np.histogram(x, bins=np.append(grid, grid[-1] + step))
    k_half = int(4 * sigma_us / step)
    kx = np.arange(-k_half, k_half + 1) * step
    kern = np.exp(-0.5 * (kx / sigma_us) ** 2)
    kern /= kern.sum()
    dens = np.convolve(hist, kern, mode="same") / (len(x) * step)
    return dens * per_us * 100.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=DEF_RESULTS)
    ap.add_argument("--out", default="tracepoint_overhead_density.png")
    ap.add_argument("--slots", nargs=3, metavar=("CTRL", "LITE", "FULL"), default=None,
                    help="slot directory names for control, lite, full (default: process-launch-f2 names)")
    args = ap.parse_args()
    if args.slots:
        for i, slot in enumerate(args.slots):
            SERIES[i] = (SERIES[i][0], slot, SERIES[i][2])

    grid = np.arange(XMIN, XMAX, 5.0)
    # constrained layout (not bbox_inches="tight") so the saved figure is exactly
    # one column wide; a trimmed figure gets scaled up by \includegraphics and the
    # point sizes below would no longer be the point sizes on the page
    fig, ax = plt.subplots(figsize=(SINGLE_COL, SINGLE_COL * 0.46), layout="constrained")
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(GRID)
    ax.tick_params(colors=INK2)
    ax.grid(axis="y", color=GRID, linewidth=0.3)
    ax.set_axisbelow(True)

    PCTS = [(50, (0, (2, 2))), (90, (0, (4, 1, 1, 1))), (99, "solid")]
    ymax = 0.0
    for label, slot, color in SERIES:
        x = load(f"{args.results}/{slot}/uartlog")
        y = smooth_pct(x, grid)
        ymax = max(ymax, float(y.max()))
        ax.plot(grid, y, color=color, linewidth=1.0)
        ax.fill_between(grid, y, color=color, alpha=0.08, linewidth=0)
        for p, ls in PCTS:
            v = np.percentile(x, p)
            ax.axvline(v, color=color, linewidth=0.5, linestyle=ls, alpha=0.85)


    ytop = ymax * 1.16
    ax.set_xlim(XMIN, XMAX)
    ax.set_ylim(0, ytop)

    ax.set_xlabel("Process launch latency (µs)", color=INK2)
    ax.set_ylabel("Launches (%)", color=INK2)

    # direct labels: control on its mode, lite/full on the drain bumps, which is
    # the only place the two tracepoint sets separate
    ax.text(752, ymax * 1.02, "control", color="#2a78d6", fontsize=8,
            fontweight="bold", ha="center", va="bottom")
    ax.text(1294, ytop * 0.14, "lite", color="#1baf7a", fontsize=8,
            fontweight="bold", ha="center", va="bottom")
    ax.text(1424, ytop * 0.19, "full", color="#eda100", fontsize=8,
            fontweight="bold", ha="center", va="bottom")

    handles = [plt.Line2D([], [], color=INK2, linewidth=0.5,
                          linestyle=(0, (2, 2)), label="p50"),
               plt.Line2D([], [], color=INK2, linewidth=0.5,
                          linestyle=(0, (4, 1, 1, 1)), label="p90"),
               plt.Line2D([], [], color=INK2, linewidth=0.5, label="p99")]
    # sits in the line-free gap between the control p99 and the lite p90
    ax.legend(handles=handles, loc="upper left", bbox_to_anchor=(0.51, 1.03),
              frameon=False, labelcolor=INK, handlelength=1.8, labelspacing=0.2,
              borderpad=0.0, handletextpad=0.5)
    fig.savefig(args.out)
    print("saved", args.out)


if __name__ == "__main__":
    main()
