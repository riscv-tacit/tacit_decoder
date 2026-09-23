#!/usr/bin/env python3
"""Paper figure: process-launch latency tail, control vs fix (RCU GP kthread on SCHED_BATCH).

Single panel: complementary CDF (fraction of launches slower than a given latency) on a
log axis -- the fix truncates the tail; the body is identical and is not shown.

Reads "N: <ns>" lines from the two untraced 10k-spawn uartlogs.
Usage: plot_fix_ccdf.py [--results DIR] [--out PREFIX]
"""
import argparse
import re

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np

MM = 1 / 25.4
mpl.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["Arial", "Helvetica", "DejaVu Sans"],
    "font.size": 8, "axes.labelsize": 8, "axes.titlesize": 8,
    "xtick.labelsize": 7, "ytick.labelsize": 7, "legend.fontsize": 7,
    "axes.linewidth": 0.6, "xtick.major.width": 0.5, "ytick.major.width": 0.5,
    "xtick.major.size": 2.5, "ytick.major.size": 2.5,
    "lines.linewidth": 1.0, "pdf.fonttype": 42, "ps.fonttype": 42, "savefig.dpi": 300,
})

DEF_RESULTS = ("/home/ubuntu/work/f2-chipyard/sims/firesim/deploy/results-workload/"
               "2026-09-06--21-38-19-process-launch-f2")
SERIES = [  # label, slot, Okabe-Ito color, linestyle
    ("control", "process-launch-f2-collect-10k", "#0072B2", "-"),
    ("fix", "process-launch-f2-collect-10k-fix", "#D55E00", "--"),
]
GRID = "#d9d9d9"


def load(path):
    raw = open(path, "rb").read().decode("utf-8", "replace")
    x = np.array([int(m) for m in re.findall(r"^\d+: (-?\d+)\r*$", raw, re.M)], dtype=float)
    return x[x >= 0] / 1000.0  # us; drop tv_nsec wraps


def density(x, grid, sigma=8.0):
    step = grid[1] - grid[0]
    hist, _ = np.histogram(x, bins=np.append(grid, grid[-1] + step))
    k = np.arange(-int(4 * sigma / step), int(4 * sigma / step) + 1) * step
    kern = np.exp(-0.5 * (k / sigma) ** 2)
    kern /= kern.sum()
    return np.convolve(hist, kern, mode="same") / len(x) * 100.0  # % of launches per bin


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=DEF_RESULTS)
    ap.add_argument("--out", default="fix_ccdf")
    args = ap.parse_args()

    data = {lab: load(f"{args.results}/{slot}/uartlog") for lab, slot, _, _ in SERIES}

    # constrained layout (not bbox_inches="tight") so the saved figure is exactly
    # one column wide and the point sizes above are the point sizes on the page
    fig, b = plt.subplots(figsize=(89 * MM, 89 * MM * 0.52), layout="constrained")
    b.spines[["top", "right"]].set_visible(False)
    b.grid(axis="y", color=GRID, linewidth=0.3)
    b.set_axisbelow(True)
    b.set_xlabel("Process launch latency (µs)")

    # tail as a complementary CDF (survival curve)
    for lab, _, c, ls in SERIES:
        x = np.sort(data[lab])
        ccdf = 1.0 - np.arange(1, len(x) + 1) / len(x)
        ccdf[-1] = 1.0 / len(x)  # keep the max on the log axis
        b.step(x, ccdf, where="post", color=c, ls=ls)
        b.plot([x[-1]], [1.0 / len(x)], marker="o", ms=2.5, color=c, mec=c)
    b.set_yscale("log")
    b.set_xlim(700, 1500)
    b.set_ylim(8e-5, 1.2)
    b.set_ylabel("Fraction slower")
    b.set_yticks([1, 1e-1, 1e-2, 1e-3, 1e-4])
    b.set_yticklabels(["1", "10⁻¹", "10⁻²", "10⁻³", "10⁻⁴"])
    # the 10^-2 / 10^-3 gridlines are p99 / p99.9; the values are given in the
    # per-series blocks below, so no extra rules or labels are needed here

    # narrow 4-line blocks, parked in the two dead corners of the log axis
    pos = {"control": (1497, 2.0e-2, "right"), "fix": (706, 1.15e-4, "left")}
    for lab, _, c, ls in SERIES:
        x = data[lab]
        p99, p999, mx = np.percentile(x, 99), np.percentile(x, 99.9), x.max()
        tx, ty, ha = pos[lab]
        b.text(tx, ty, f"{lab}\np99 {p99:.0f}\np99.9 {p999:.0f}\nmax {mx:.0f} µs",
               color=c, ha=ha, va="bottom", fontsize=7, linespacing=1.25)
        b.plot([mx], [1.0 / len(x)], marker="o", ms=3, color=c, mec=c)

    fig.savefig(f"{args.out}.pdf")
    fig.savefig(f"{args.out}.png", dpi=300)
    print(f"wrote {args.out}.pdf/.png")


if __name__ == "__main__":
    main()
