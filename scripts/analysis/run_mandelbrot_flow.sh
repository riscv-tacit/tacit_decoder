#!/usr/bin/env bash
# The mandelbrot analysis flow, parameterised by capture so that a baseline and a
# fused variant are produced by *identical* commands and their output directories
# diff cleanly. Every knob is fixed here, not passed in: differing parameters are
# how two "comparable" folders quietly stop being comparable.
set -euo pipefail
PY=/scratch/iansseijelly/tacit-chipyard/.conda-env/bin/python3
S=scripts/analysis

OPTAB=$1        # handler address -> opcode name, for THIS binary
PREFIX=$2       # <prefix>.{bb_stats,bb_hist,bb_pair_stats,dispatch_stats,dispatch_hist}.csv
WINDOW=$3       # guest window in seconds (window_cycles / 1e9, 1 GHz target)
OUT=$4
mkdir -p "$OUT"

$PY $S/lua_vbb.py "$PREFIX.bb_stats.csv" --optab "$OPTAB" \
    --out "$OUT/vbb.mandelbrot" --top 20

# bb_pair_stats is the memory-hungry receiver and the narrow decode config omits
# it, so the generic paired-block view is optional rather than fatal.
if [ -f "$PREFIX.bb_pair_stats.csv" ]; then
  $PY $S/lua_bb_pair_view.py --bb-stats "$PREFIX.bb_stats.csv" \
      --bb-pairs "$PREFIX.bb_pair_stats.csv" --optab "$OPTAB" \
      --out "$OUT/bbpair.mandelbrot" --top 8
else
  echo "  (no bb_pair_stats.csv -- skipping the paired-block view; re-decode with"
  echo "   configs/templates/lua-fuse-vbb.json if you want it)"
fi

$PY $S/lua_pair_latency_report.py --optab "$OPTAB" \
    --stats "$PREFIX.dispatch_stats.csv" --window "$WINDOW" \
    --out "$OUT/pairs.mandelbrot"

# the per-block histogram needs bb_stats' hist_path; a decode without it still has
# everything else, so skip the figure rather than the flow
if [ -f "$PREFIX.bb_hist.csv" ]; then
  $PY $S/plot_bb_distributions.py --bb-stats "$PREFIX.bb_stats.csv" \
      --bb-hist "$PREFIX.bb_hist.csv" --optab "$OPTAB" \
      --top 5 --cols 3 --min-range 3 --percentiles 50,90,99 \
      -o "$OUT/fig.bb_distributions.pdf"
else
  echo "  (no bb_hist.csv -- skipping fig.bb_distributions; add hist_path to bb_stats to get it)"
fi

$PY $S/plot_pred_distributions.py --hist "$PREFIX.dispatch_hist.csv" \
    --optab "$OPTAB" --targets top:2 --bb-stats "$PREFIX.bb_stats.csv" \
    --out "$OUT/fig.pred_distributions"

echo "flow complete -> $OUT"
