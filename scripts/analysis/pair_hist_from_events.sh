#!/usr/bin/env bash
# True per-instance histogram of each (OP0 -> OP1) entry-block latency, from a raw
# `txt` receiver dump. Mirrors dispatch_stats_receiver.rs: an event whose next BB starts
# at a handler entry opens a pending interval; the following event closes it. Flow resets
# on anything that is not one of the four control-flow kinds (sync/trap), exactly as the
# receiver does, so no interval spans a discontinuity.
#
#   pair_hist_from_events.sh trace.mandelbrot.events.txt optab.csv out.hist.csv
# optab.csv is "0xaddr,OPNAME" per line.  Output: op0,op1,cycles,count
set -eu
EVENTS=$1; OPTAB=$2; OUT=$3
awk -v optab="$OPTAB" '
BEGIN {
  while ((getline line < optab) > 0) { split(line, a, ","); H[a[1]] = a[2] }
  FS = " "; cur = ""; pend = 0
}
{
  kind = $3
  if (kind != "InferrableJump:" && kind != "UninferableJump:" &&
      kind != "TakenBranch:" && kind != "NonTakenBranch:") { cur = ""; pend = 0; next }
  ts = $2; sub(/\]/, "", ts); to = $NF
  if (pend) {
    d = ts - pts
    if (d >= 0 && d <= 200 && pfrom != "") cnt[pfrom "," pto "," d]++
    pend = 0
  }
  if (to in H) { pfrom = cur; pto = H[to]; pts = ts; pend = 1; cur = H[to] }
}
END { print "op0,op1,cycles,count"; for (k in cnt) print k "," cnt[k] }
' "$EVENTS" > "$OUT"
echo "wrote $OUT ($(wc -l < "$OUT") rows)"
