#!/usr/bin/env python3
"""BB-level error epsilon(BB) = sum_i |t_i - that_i| / sum_i t_i over the
per-instance BB sequence, with the TraceDoctor oracle as reference {t} and
TACIT-decoded inter-event deltas as emulated {that}.

Inputs:
  --tacit    tacit-decoder txt output (event lines are parsed)
  --oracle   bboracle per-instance csv (10-col with exit_tsc; older rejected)

Instance k (k>=1) is entered at event k-1 (arc target) and exited at event
k; residency estimate = the forward delta between consecutive events. The
two windows have different leading margins and may diverge sparsely
mid-stream (Linux traps, foreign-asid excursions); a windowed resync search
skips the minimal number of rows on either side and reports coverage.

Both inputs are STREAMED with bounded lookahead windows, so memory stays
O(resync window) regardless of run length (SPEC captures reach billions of
instances).

Reports epsilon plus its decomposition into sub-cycle quantization (|d| < 1)
and semantic movement (|d| >= 1).
"""

import argparse
import re
import sys
from collections import deque

RX = re.compile(r"\[timestamp: (\d+)\] (\w+): (0x[0-9a-f]+) -> (0x[0-9a-f]+)")

RESYNC_INST_WINDOW = 8192  # max oracle instances skipped at one divergence
RESYNC_EV_WINDOW = 64      # max tacit events skipped at one divergence
RESYNC_PROBE = 8           # consecutive matches required to accept a lock

BB_HEADER = ("entry_tsc,exit_tsc,bb_pc,prv,asid,retired,computing_x12,"
             "stalled_x12,flushed_x12,drained_x12")


def _open(path):
    """Plain or zstd-compressed text; .zst is streamed, never materialized
    (raw per-instance csvs reach ~100GB at SPEC scale)."""
    if str(path).endswith(".zst"):
        import subprocess
        p = subprocess.Popen(["zstd", "-dc", str(path)],
                             stdout=subprocess.PIPE, text=True,
                             bufsize=1 << 20)
        return p.stdout
    return open(path)


def iter_events(path):
    with _open(path) as f:
        for line in f:
            m = RX.match(line)
            if m:
                yield (int(m.group(1)), m.group(4))


def iter_instances(path, user_asids, stats):
    """Yield (bb_pc, cycles, exit_tsc, ref_delta); stats['dropped'] counts
    filtered foreign-asid user rows. Rejects pre-exit_tsc captures.

    ref_delta is exit_tsc minus the exit_tsc of this row's immediate
    predecessor in the RAW csv -- tracked before filtering, so neither asid
    drops nor downstream resync skips can stretch it across a gap. It is
    exactly what TACIT would report if its transport were lossless, and so
    serves as the paired reference floor."""
    prev_raw_exit = None
    with _open(path) as f:
        header = f.readline().strip()
        if header != BB_HEADER:
            sys.exit(f"{path}: old-format bboracle csv (header '{header}'); "
                     "re-capture with the prv/asid+exit_tsc bitstream/driver")
        for line in f:
            p = line.split(",")
            if len(p) != 10:
                continue
            ex = int(p[1])
            if user_asids is not None and p[3] == "0" \
                    and int(p[4]) not in user_asids:
                stats["dropped"] += 1
                prev_raw_exit = ex
                continue
            yield (p[2],
                   (int(p[6]) + int(p[7]) + int(p[8]) + int(p[9])) / 12.0,
                   ex,
                   None if prev_raw_exit is None else ex - prev_raw_exit)
            prev_raw_exit = ex


class Window:
    """Bounded forward window over an iterator with relative indexing."""

    __slots__ = ("it", "buf", "exhausted")

    def __init__(self, it):
        self.it = it
        self.buf = deque()
        self.exhausted = False

    def fill(self, n):
        buf, it = self.buf, self.it
        while len(buf) < n and not self.exhausted:
            try:
                buf.append(next(it))
            except StopIteration:
                self.exhausted = True
        return len(buf)

    def drain_count(self):
        n = len(self.buf)
        for _ in self.it:
            n += 1
        return n


def probe_window(I, E, di, dk, n):
    ni = I.fill(di + n) - di
    nk = E.fill(dk + n) - dk
    n = min(n, ni, nk)
    if n <= 0:
        return False
    ib, eb = I.buf, E.buf
    return all(ib[di + j][0] == eb[dk + j][1] for j in range(n))


# list-compatible variant kept for external users (proxy_vs_measured)
def probe_match(instances, targets, i, k, n):
    if i + n > len(instances) or k + n > len(targets):
        n = min(len(instances) - i, len(targets) - k)
        if n <= 0:
            return False
    return all(instances[i + j][0] == targets[k + j] for j in range(n))


def parse_instances(path, user_asids):
    """In-memory variant for small captures / external scripts."""
    stats = {"dropped": 0}
    out = list(iter_instances(path, user_asids, stats))
    if stats["dropped"]:
        print(f"filtered {stats['dropped']} foreign-asid user instances "
              f"(user asids kept: {sorted(user_asids)})")
    return out


def proxy_epsilon(path):
    """Oracle-only epsilon: emulate TACIT's estimate from the oracle's own
    EXIT timestamps -- that_k = exit_tsc(k) - exit_tsc(k-1). TACIT stamps
    events at CFI retirement, so exit-to-exit is its slicing. No asid
    filtering: the delta chain must stay contiguous."""
    num = den = num_q = num_s = 0.0
    cq = cs = pairs = 0
    stats = {"dropped": 0}
    prev_exit = None
    for bb, t, ex, _rd in iter_instances(path, None, stats):
        if prev_exit is not None:
            that = ex - prev_exit
            d = abs(t - that)
            num += d
            den += t
            pairs += 1
            if d >= 1.0:
                num_s += d
                cs += 1
            elif d > 0:
                num_q += d
                cq += 1
        prev_exit = ex
    if den == 0:
        sys.exit("proxy: no instances")
    print(f"proxy pairs: {pairs} (all consecutive instances, unfiltered)")
    print(f"epsilon_proxy(BB) = {100 * num / den:.2f}%   "
          f"(sum|d| {num:.0f} / sum t {den:.0f})")
    print(f"  quantization (|d|<1): {100 * num_q / den:.2f}%  ({cq} instances)")
    print(f"  semantic (|d|>=1):    {100 * num_s / den:.2f}%  ({cs} instances)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tacit", help="decoded tacit txt (omit with --proxy)")
    ap.add_argument("--oracle", required=True)
    ap.add_argument("--asids", default=None,
                    help="comma-separated user asids the decoder can "
                         "symbolize; other user-mode instances are dropped")
    ap.add_argument("--proxy", action="store_true",
                    help="oracle-only epsilon from exit_tsc deltas; no "
                         "tacit capture involved")
    args = ap.parse_args()

    if args.proxy:
        proxy_epsilon(args.oracle)
        return
    if not args.tacit:
        sys.exit("--tacit is required unless --proxy is given")

    user_asids = (set(int(a) for a in args.asids.split(","))
                  if args.asids else None)
    istats = {"dropped": 0}
    I = Window(iter_instances(args.oracle, user_asids, istats))
    E = Window(iter_events(args.tacit))

    # start at (instance 1, event 0); instance 0's entry is unobservable
    I.fill(2) and I.buf.popleft()

    num = den = num_q = num_s = 0.0
    cq = cs = matched = 0
    resyncs = skip_i = skip_k = 0
    # paired reference floor: same matched instances, same den, but that_ref
    # is the oracle's own exit-to-exit delta -- what a lossless TACIT would
    # emit. num - num_ref is therefore TACIT's own error, free of the
    # attribution-convention gap that both estimators share.
    num_ref = 0.0
    cs_ref = ref_pairs = 0

    ibuf, ebuf = I.buf, E.buf
    while I.fill(1) and E.fill(2) >= 1:
        if ibuf[0][0] == ebuf[0][1]:
            if len(ebuf) >= 2:
                t = ibuf[0][1]
                that = ebuf[1][0] - ebuf[0][0]
                d = t - that
                if d < 0:
                    d = -d
                num += d
                den += t
                matched += 1
                if d >= 1.0:
                    num_s += d
                    cs += 1
                elif d > 0:
                    num_q += d
                    cq += 1
                rd = ibuf[0][3]
                if rd is not None:
                    dr = t - rd
                    if dr < 0:
                        dr = -dr
                    num_ref += dr
                    ref_pairs += 1
                    if dr >= 1.0:
                        cs_ref += 1
            ibuf.popleft()
            ebuf.popleft()
            continue
        # divergence: minimal-total skip that re-locks for RESYNC_PROBE rows
        I.fill(RESYNC_INST_WINDOW)
        E.fill(RESYNC_EV_WINDOW + 1 + RESYNC_PROBE)
        upcoming = {}
        for di in range(len(ibuf) if len(ibuf) < RESYNC_INST_WINDOW
                        else RESYNC_INST_WINDOW):
            upcoming.setdefault(ibuf[di][0], []).append(di)
        best = None
        for dk in range(min(RESYNC_EV_WINDOW + 1, len(ebuf))):
            for di in upcoming.get(ebuf[dk][1], []):
                if (di, dk) == (0, 0):
                    continue
                if best and di + dk >= best[0] + best[1]:
                    break
                if probe_window(I, E, di, dk, RESYNC_PROBE):
                    best = (di, dk)
                    break
        if best is None:
            print(f"resync failed (inst bb {ibuf[0][0]}, target "
                  f"{ebuf[0][1]}); truncating comparison here")
            break
        resyncs += 1
        skip_i += best[0]
        skip_k += best[1]
        for _ in range(best[0]):
            ibuf.popleft()
        for _ in range(best[1]):
            ebuf.popleft()

    tail_i = I.drain_count()
    tail_k = E.drain_count()
    if istats["dropped"]:
        print(f"filtered {istats['dropped']} foreign-asid user instances "
              f"(user asids kept: {sorted(user_asids)})")
    print(f"matched: {matched} pairs "
          f"(resyncs: {resyncs}, skipped {skip_i} inst / {skip_k} ev "
          f"mid-stream; tail: {tail_i} inst / {tail_k} ev)")
    total_pairs = matched + skip_i + skip_k
    if matched:
        print(f"coverage: {100.0 * matched / max(1, total_pairs):.2f}% of "
              "aligned rows")
    if den == 0:
        sys.exit("no comparable pairs")
    print(f"epsilon(BB) = {100 * num / den:.2f}%   (sum|d| {num:.0f} / sum t {den:.0f})")
    print(f"  quantization (|d|<1): {100 * num_q / den:.2f}%  ({cq} instances)")
    print(f"  semantic (|d|>=1):    {100 * num_s / den:.2f}%  ({cs} instances)")
    if ref_pairs:
        eps_ref = 100 * num_ref / den
        print(f"reference floor      = {eps_ref:.2f}%   "
              f"(same {ref_pairs} matched instances, oracle exit deltas; "
              f"{cs_ref} with |d|>=1)")
        print(f"  attributable to TACIT: {100 * num / den - eps_ref:+.2f} pp")


if __name__ == "__main__":
    main()
