# SUPERSEDED for vbb work by plot_vbb_share.py, which reads the bb_stats receiver
# CSV directly and ranks on vbb = n*(mean-p5). Kept for the SPEC sqlite flow
# (trace_db_tools bb-stats --outdir), whose netvar ranking it still reproduces.
import matplotlib
import matplotlib.pyplot as plt
# plt.style.use('seaborn-v0_8-colorblind')
# plt.rc('font', family='serif')
# plt.rc('font', serif='Latin Modern Roman')
matplotlib.rcParams.update({'font.size': 16})
import pandas as pd
import numpy as np
import os
import sys
import argparse

BENCHMARKS = [
    "perlbench", "gcc", "mcf", "omnetpp", "xalancbmk", "x264",
    "leela", "exchange2", "xz-cpu2006docs", "xz-cld", 
]


def load_data(base_dir):
    """Load top_by_netvar.csv, top_by_total.csv, and summary.txt for each benchmark."""
    data = {}
    for name in BENCHMARKS:
        bdir = os.path.join(base_dir, name)
        if not os.path.isdir(bdir):
            print(f"WARNING: skipping {name}, directory not found", file=sys.stderr)
            continue
        netvar_df = pd.read_csv(os.path.join(bdir, "top_by_netvar.csv"))
        total_df = pd.read_csv(os.path.join(bdir, "top_by_total.csv"))

        # Parse total_cycles from summary.txt
        total_cycles = None
        total_netvar = None
        with open(os.path.join(bdir, "summary.txt")) as f:
            for line in f:
                if "Total cycles:" in line:
                    total_cycles = int(line.strip().split()[-1])
                if "Total netvar:" in line:
                    total_netvar = int(line.strip().split()[-1])

        data[name] = {
            "netvar": netvar_df,
            "total": total_df,
            "total_cycles": total_cycles,
            "total_netvar": total_netvar,
        }
        print(f"--------------------------------")
        print(f"Loaded {name} with total_cycles={total_cycles}", file=sys.stderr)
    return data


def plot_top_netvar_tc_stacked(data, outpath):
    """Stacked bar chart: top 10 netvar BBs as % of total cycles per benchmark."""
    fig, ax = plt.subplots(figsize=(10, 6))

    names = list(data.keys())
    n = len(names)
    x = range(n)

    # For each benchmark, compute per-BB percentage of total cycles
    # Stack from bottom (rank 1) to top (rank 10)
    max_rank = 10
    bottoms = [0.0] * n
    colors = plt.cm.rainbow(np.linspace(0, 1, 10))                                                                                                                                                                   

    for rank in range(max_rank):
        heights = []
        for name in names:
            d = data[name]
            df = d["netvar"]
            tc = d["total_cycles"]
            if rank < len(df) and tc and tc > 0:
                pct = df.iloc[rank]["netvar"] / tc * 100
                # print(f"Rank {rank+1} of {name} has {pct}% of total netvar", file=sys.stderr)
            else:
                pct = 0.0
            heights.append(pct)
        ax.bar(x, heights, bottom=bottoms, color=colors[rank],
               label=f"Rank {rank+1}", edgecolor="white", linewidth=0.3)
        bottoms = [b + h for b, h in zip(bottoms, heights)]

    # Add "rest" bar to show what fraction is NOT in top 10
    rest = []
    for i, name in enumerate(names):
        rest.append(100.0 - bottoms[i])
    ax.bar(x, rest, bottom=bottoms, color="#e0e0e0", label="Other BBs",
           edgecolor="white", linewidth=0.3)
    for i in range(n):
        ax.text(i, bottoms[i] + rest[i] / 2, f"{rest[i]:.0f}%", ha="center", va="center", color="#555555")

    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=35, ha="right")
    ax.set_ylabel("% of Total Cycles")
    ax.set_title("Top 10 BBs by Netvar: Share of Total Cycles")
    # ax.legend(bbox_to_anchor=(1.02, 1), loc="upper left")
    ax.set_ylim(0, 100)
    fig.tight_layout()
    fig.savefig(outpath, dpi=150)
    plt.close(fig)
    print(f"Saved {outpath}", file=sys.stderr)

def plot_top_netvar_tn_stacked(data, outpath):
    """Stacked bar chart: top 10 netvar BBs as % of total cycles per benchmark."""
    fig, ax = plt.subplots(figsize=(10, 6))

    names = list(data.keys())
    n = len(names)
    x = range(n)

    # For each benchmark, compute per-BB percentage of total cycles
    # Stack from bottom (rank 1) to top (rank 10)
    max_rank = 10
    bottoms = [0.0] * n
    colors = plt.cm.rainbow(np.linspace(0, 1, 10))                                                                                                                                                                   

    for rank in range(max_rank):
        heights = []
        for name in names:
            d = data[name]
            df = d["netvar"]
            tn = d["total_netvar"]
            if rank < len(df) and tn and tn > 0:
                pct = df.iloc[rank]["netvar"] / tn * 100
                # print(f"Rank {rank+1} of {name} has {pct}% of total netvar", file=sys.stderr)
            else:
                pct = 0.0
            heights.append(pct)
        ax.bar(x, heights, bottom=bottoms, color=colors[rank],
               label=f"Rank {rank+1}", edgecolor="white", linewidth=0.3)
        bottoms = [b + h for b, h in zip(bottoms, heights)]

    # Add "rest" bar to show what fraction is NOT in top 10
    rest = []
    for i, name in enumerate(names):
        rest.append(100.0 - bottoms[i])
    ax.bar(x, rest, bottom=bottoms, color="#e0e0e0", label="Other BBs",
           edgecolor="white", linewidth=0.3)
    for i in range(n):
        ax.text(i, bottoms[i] + rest[i] / 2, f"{rest[i]:.0f}%", ha="center", va="center", color="#555555")

    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=35, ha="right")
    ax.set_ylabel("% of Total Netvar")
    ax.set_title("Top 10 BBs by Netvar: Share of Total Netvar")
    # ax.legend(bbox_to_anchor=(1.02, 1), loc="upper left")
    ax.set_ylim(0, 100)
    fig.tight_layout()
    fig.savefig(outpath, dpi=150)
    plt.close(fig)
    print(f"Saved {outpath}", file=sys.stderr)


def plot_rank_comparison(data, outpath):
    """Bump chart per benchmark: netvar rank (left) vs total rank (right) with connecting lines."""
    names = list(data.keys())
    n = len(names)
    cols = 5
    rows = (n + cols - 1) // cols
    fig, axes = plt.subplots(rows, cols, figsize=(4 * cols, 4 * rows))
    axes = axes.flatten()

    colors = plt.cm.rainbow(np.linspace(0, 1, 10))                                                                                                                                                                   
  
    for idx, name in enumerate(names):
        ax = axes[idx]
        netvar_df = data[name]["netvar"]
        total_df = data[name]["total"]

        # Build rank maps: bb -> rank (1-indexed)
        netvar_rank = {bb: i + 1 for i, bb in enumerate(netvar_df["bb"])}
        total_rank = {bb: i + 1 for i, bb in enumerate(total_df["bb"])}
        all_bbs = list(dict.fromkeys(list(netvar_df["bb"]) + list(total_df["bb"])))

        max_rank = max(len(netvar_df), len(total_df))
        unranked = max_rank + 1.5  # position for BBs not in a list

        for i, bb in enumerate(all_bbs):
            nr = netvar_rank.get(bb)
            tr = total_rank.get(bb)
            left = nr if nr else unranked
            right = tr if tr else unranked

            if nr and tr:
                # In both lists — solid colored line
                c = colors[(nr - 1) % 10]
                ax.plot([0, 1], [left, right], color=c, linewidth=1.5, alpha=0.8,
                        solid_capstyle="round")
                ax.plot(0, left, "o", color=c, markersize=5)
                ax.plot(1, right, "o", color=c, markersize=5)
            elif nr:
                # Netvar only — dashed to unranked
                ax.plot([0, 1], [left, right], color="#dd8452", linewidth=1,
                        linestyle="--", alpha=0.5)
                ax.plot(0, left, "o", color="#dd8452", markersize=4)
            else:
                # Total only — dashed from unranked
                ax.plot([0, 1], [left, right], color="#55a868", linewidth=1,
                        linestyle="--", alpha=0.5)
                ax.plot(1, right, "o", color="#55a868", markersize=4)

        ax.set_xlim(-0.3, 1.3)
        ax.set_ylim(unranked + 0.5, 0.5)
        ax.set_xticks([0, 1])
        ax.set_xticklabels(["Netvar", "Total"])
        ax.set_yticks(range(1, max_rank + 1))
        ax.set_ylabel("Rank")
        ax.set_title(name, fontweight="bold")
        ax.axhline(y=max_rank + 0.75, color="gray", linewidth=0.5, linestyle=":")

    # Hide unused subplots
    for idx in range(n, len(axes)):
        axes[idx].set_visible(False)

    fig.suptitle("Rank Comparison: Netvar vs Total Time (top 10)", y=1.01)
    fig.tight_layout()
    fig.savefig(outpath, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved {outpath}", file=sys.stderr)


def plot_overlap(data, outpath):
    """Bar chart: number of overlapping BBs between top-10 netvar and top-10 total rankings."""
    fig, ax = plt.subplots(figsize=(10, 6))

    names = list(data.keys())
    n = len(names)
    x = range(n)

    overlaps = []
    for name in names:
        netvar_bbs = set(data[name]["netvar"]["bb"])
        total_bbs = set(data[name]["total"]["bb"])
        overlaps.append(len(netvar_bbs & total_bbs))

    bars = ax.bar(x, overlaps, color="#4c72b0", edgecolor="white", linewidth=0.3)
    for i, v in enumerate(overlaps):
        ax.text(i, v + 0.15, str(v), ha="center", va="bottom")

    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=35, ha="right")
    ax.set_ylabel("Overlapping BBs")
    ax.set_title("Top 10 Overlap: Netvar vs Total Time Rankings")
    ax.set_ylim(0, 11)
    ax.axhline(y=10, color="gray", linewidth=0.5, linestyle="--")
    fig.tight_layout()
    fig.savefig(outpath, dpi=150)
    plt.close(fig)
    print(f"Saved {outpath}", file=sys.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plot BB stats across benchmarks")
    parser.add_argument("--indir", required=True, help="Base directory with per-benchmark subdirs")
    parser.add_argument("--outdir", default=".", help="Directory for output PNGs")
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    data = load_data(args.indir)

    plot_top_netvar_tc_stacked(data, os.path.join(args.outdir, "top_netvar_tc_share.png"))
    plot_top_netvar_tn_stacked(data, os.path.join(args.outdir, "top_netvar_tn_share.png"))
    plot_rank_comparison(data, os.path.join(args.outdir, "netvar_vs_total_rank.png"))
    plot_overlap(data, os.path.join(args.outdir, "netvar_vs_total_overlap.png"))
