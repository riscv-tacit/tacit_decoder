#!/usr/bin/env python3
"""One loop iteration under both clocks, event by event.

Replays the TNT+CYC (tnt_cyc_nret) emulator (cumulative-rounding split) over the reference bb_seq dump: taken/not-taken
branches and inferable jumps are staged without a timestamp; an uninferable jump, a trap, or
the N-th staged branch flushes with an exact stamp and spreads the elapsed cycles evenly
over the staged events. The replay is checked against the decoder's own emulated
dispatch_seq (handler-entry timestamps), which it must reproduce exactly.

Then prints, for the k-th occurrence of a handler pattern (default: mandelbrot's inner loop),
every basic block of that iteration: address range, kind of arc that ended it, reference
latency, whether that arc carried a stamp, and emulated latency; plus per-handler spans
under both clocks.

  lua_smear_trace.py --optab configs/lua/lua_optab_mulmul_muladd.json \
      --bb-seq bundles/<b>/out-span/ref/lua.bb_seq.csv \
      --emu-seq bundles/<b>/out-span/tnt6/lua.dispatch_seq.csv --nrows 3000000 --occurrence 1000
"""
import argparse
import json

import pathlib
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

LOOP = ['LTI', 'MUL', 'MUL', 'ADD', 'LEI', 'MUL', 'MUL', 'SUB', 'ADD', 'MULK', 'MUL', 'ADD',
        'MOVE', 'ADDI', 'JMP']


def replay_tnt(ts, kind, lim=6, flags=False):
    """-> emulated timestamp per event (same order as input); with flags=True also a
    per-event marker: 'jr' / 'trap' / 'count' for events that carried an exact stamp."""
    emu = np.zeros(len(ts), dtype=np.int64)
    why = np.full(len(ts), '', dtype=object)
    staged = []            # indices
    n_tnt = 0
    curr = emu_clock = int(ts[0])
    for i in range(len(ts)):
        k = kind[i]
        if k == 'sync' or k == 'resume':
            staged.clear(); n_tnt = 0
            curr = emu_clock = int(ts[i]); emu[i] = ts[i]; why[i] = k
            continue
        if k in ('br', 'nt'):
            n_tnt += 1
        staged.append(i)
        if n_tnt >= lim or k in ('jr', 'trap'):
            why[i] = k if k in ('jr', 'trap') else 'count'
            slack = int(ts[i]) - curr
            num = len(staged)
            # cumulative rounding, as in the decoder's `share`
            for j, idx in enumerate(staged):
                emu_clock += (slack * (j + 1)) // num - (slack * j) // num
                emu[idx] = emu_clock
            staged.clear(); n_tnt = 0
            curr = int(ts[i])
    return (emu, why) if flags else emu


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--optab', required=True)
    ap.add_argument('--bb-seq', required=True)
    ap.add_argument('--emu-seq', help='decoder-emulated dispatch_seq, to verify the replay')
    ap.add_argument('--nrows', type=int, default=3_000_000)
    ap.add_argument('--lim-tnt', type=int, default=6)
    ap.add_argument('--pattern', default=','.join(LOOP))
    ap.add_argument('--occurrence', type=int, default=-1,
                    help='which occurrence of the pattern to print; -1 = the most typical one '
                         '(per-position reference spans closest to their modes)')
    ap.add_argument('--csv', help='also write the iteration table here')
    ap.add_argument('--fig', help='draw the iteration as a two-lane timeline (prefix, .pdf/.png)')
    ap.add_argument('--venue', default='acm')
    a = ap.parse_args()

    tab = {int(k, 16): v for k, v in json.load(open(a.optab)).items()}
    entry_arr = np.array(sorted(tab), dtype=np.int64)
    M63 = (1 << 63) - 1
    d = pd.read_csv(a.bb_seq, dtype={'bb_end': str, 'kind': str}, nrows=a.nrows)
    ts = d['timestamp'].to_numpy(np.int64)
    start = d['bb_start'].map(lambda s: int(s, 16) & M63).to_numpy(np.int64)
    end = d['bb_end'].map(lambda s: (int(s, 16) & M63) if isinstance(s, str) and s else -1).to_numpy(np.int64)
    kind = d['kind'].to_numpy()
    n = len(d)

    emu, why = replay_tnt(ts, kind, a.lim_tnt, flags=True)

    # handler entered by block i (exact start or entry strictly inside the block)
    idx = np.searchsorted(entry_arr, start, side='left')
    exact = (idx < len(entry_arr)) & (entry_arr[np.minimum(idx, len(entry_arr) - 1)] == start)
    idx2 = np.searchsorted(entry_arr, start, side='right')
    inside = (idx2 < len(entry_arr)) & (entry_arr[np.minimum(idx2, len(entry_arr) - 1)] <= end) & (end >= 0)
    enters = np.full(n, -1, dtype=np.int64)
    enters[exact] = entry_arr[idx[exact]]
    m = inside & ~exact
    enters[m] = entry_arr[idx2[m]]
    # mirror dispatch_stats exactly. The receiver steps only on branch/jump events; a trap,
    # sync or resume just resets the flow to its target. Hence:
    #  * an exact-start entry is counted only if the arc that landed on it was a branch/jump
    #    (a trap-return landing on a handler address is not an entry);
    #  * a contained (fall-through) entry is found when the block CLOSES with a branch/jump,
    #    whatever arc started the block, so a block cut short by a trap is never examined.
    reached_by_cfi = np.zeros(n, dtype=bool)
    reached_by_cfi[1:] = ~np.isin(kind[:-1], ('trap', 'sync', 'resume'))
    cut_by_trap = np.isin(kind, ('trap', 'sync', 'resume'))
    enters[exact & ~reached_by_cfi] = -1
    enters[m & cut_by_trap] = -1
    ent_pos = np.flatnonzero(enters >= 0)
    ent_op = np.array([tab[e] for e in enters[ent_pos]])
    # a block's start time is the previous event's timestamp
    ent_ts_ref = ts[ent_pos - 1]
    ent_ts_emu = emu[ent_pos - 1]

    # ---- verify the replay against the decoder's emulated dispatch_seq
    if a.emu_seq:
        es = pd.read_csv(a.emu_seq, nrows=len(ent_pos) + 10)
        got = es['timestamp'].to_numpy(np.int64)
        k = min(len(got), len(ent_ts_emu)) - 1
        # skip the first entry (before the first sync the replay has no reference)
        diff = got[1:k] - ent_ts_emu[1:k]
        print(f'replay check vs {a.emu_seq}: {k-1:,} handler entries compared, '
              f'max |Δ| = {np.abs(diff).max()} cycles, mismatches = {(diff != 0).sum():,}')

    # ---- find the k-th occurrence of the pattern
    pat = a.pattern.split(',')
    L = len(pat)
    hits = [i for i in range(len(ent_op) - L) if list(ent_op[i:i + L]) == pat]
    if a.occurrence >= len(hits):
        raise SystemExit(f'only {len(hits)} occurrences of the pattern in {n:,} events')
    if a.occurrence < 0:
        spans = np.array([[ts[ent_pos[i + j + 1] - 1] - ts[ent_pos[i + j] - 1] for j in range(L)] for i in hits])
        modes = np.array([np.bincount(spans[:, j]).argmax() for j in range(L)])
        score = np.abs(spans - modes).sum(axis=1)
        occ = int(np.argmin(score))
        print(f'\nmodal reference spans per position: {modes.tolist()} (sum {modes.sum()});'
              f' most typical occurrence #{occ} deviates by {score[occ]} cycles in total,'
              f' {int((score == 0).sum()):,} of {len(hits):,} occurrences match the modes exactly')
    else:
        occ = a.occurrence
    h = hits[occ]
    print(f'\npattern {"->".join(pat)}: {len(hits):,} occurrences; showing #{occ}\n')

    b0, b1 = ent_pos[h], ent_pos[h + L]
    t0r, t0e = ts[b0 - 1], emu[b0 - 1]
    rows = []
    hidx = h
    print(f"{'handler':7s} {'block':22s} {'ends by':7s} {'stamp':5s} {'ref t':>6s} {'ref lat':>7s} {'emu t':>6s} {'emu lat':>7s}")
    for i in range(b0, b1):
        if i == ent_pos[hidx]:
            op = ent_op[hidx]; hidx += 1
            print(f"-- {op}")
        else:
            op = ''
        stamped = why[i]
        rl, el = ts[i] - ts[i - 1], emu[i] - emu[i - 1]
        blk = f'{start[i]:#x}-{end[i]:#x}' if end[i] >= 0 else f'{start[i]:#x}-'
        print(f"{'':7s} {blk:22s} {kind[i]:7s} {stamped:5s} {ts[i]-t0r:6d} {rl:7d} {emu[i]-t0e:6d} {el:7d}")
        rows.append(dict(handler=op, block=blk, kind=kind[i], stamp=stamped, ref_t=int(ts[i]-t0r),
                         ref_lat=int(rl), emu_t=int(emu[i]-t0e), emu_lat=int(el)))
    print('\nper-handler span (entry to next entry), reference vs emulated:')
    print(f"{'handler':7s} {'ref':>5s} {'emu':>5s} {'Δ':>4s}   entered by")
    for j in range(h, h + L):
        p, q = ent_pos[j], ent_pos[j + 1]
        r, e = ts[q - 1] - ts[p - 1], emu[q - 1] - emu[p - 1]
        print(f"{ent_op[j]:7s} {r:5d} {e:5d} {e - r:+4d}   {kind[p - 1]}")
    r_tot = ts[b1 - 1] - ts[b0 - 1]; e_tot = emu[b1 - 1] - emu[b0 - 1]
    print(f"{'total':7s} {r_tot:5d} {e_tot:5d} {e_tot - r_tot:+4d}")
    if a.csv:
        pd.DataFrame(rows).to_csv(a.csv, index=False)
    if a.fig:
        hs = [(ent_op[j], ts[ent_pos[j] - 1] - t0r, emu[ent_pos[j] - 1] - t0e, kind[ent_pos[j] - 1])
              for j in range(h, h + L)]
        stamps = [(ts[i] - t0r, why[i]) for i in range(b0 - 1, b1) if why[i]]
        draw_timeline(hs, r_tot, stamps, a.fig, a.venue)


def draw_timeline(hs, total, stamps, out, venue):
    """Two lanes over one iteration: the accurate handler boundaries above, the emulated ones
    below, and between them the stamps the emulated clock actually had. Guarded (unstamped)
    boundaries are coral; each lane carries the handler spans as numbers."""
    import matplotlib as mpl
    mpl.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch
    from matplotlib.lines import Line2D
    from paper_palette import MM, NAVY, CORAL, NEUTRAL, INK, INK2, style, save, tint
    st = style(venue=venue)
    width, height = st['single'], 46.0
    fig, ax = plt.subplots(figsize=(width * MM, height * MM))
    fig.subplots_adjust(left=0.11, right=0.995, top=0.99, bottom=0.36)
    yA, yE, hgt = 1.0, 0.0, 0.34
    ends_r = [x[1] for x in hs[1:]] + [total]
    ends_e = [x[2] for x in hs[1:]] + [total]
    for (op, tr, te, kd), er, ee in zip(hs, ends_r, ends_e):
        guarded = kd == 'br'
        for y, t0, t1 in ((yA, tr, er), (yE, te, ee)):
            face = tint(NAVY, 0.80) if op in ('MUL', 'ADD') else NEUTRAL
            ax.add_patch(plt.Rectangle((t0, y - hgt / 2), t1 - t0, hgt, facecolor=face,
                                       edgecolor='white', linewidth=0.5))
            if t1 - t0 >= 12:
                ax.text((t0 + t1) / 2, y, op, ha='center', va='center', fontsize=st['tick'], color=INK)
            ax.text((t0 + t1) / 2, y + (hgt / 2 + 0.07) * (1 if y == yA else -1), f'{t1 - t0}',
                    ha='center', va='bottom' if y == yA else 'top', fontsize=st['tick'],
                    color=CORAL if guarded else INK2)
        # the boundary that starts this handler, in both lanes
        col = CORAL if guarded else INK
        ax.plot([tr, tr], [yA - hgt / 2, yA + hgt / 2], color=col, linewidth=1.0)
        ax.plot([te, te], [yE - hgt / 2, yE + hgt / 2], color=col, linewidth=1.0)
        if guarded:
            ax.plot([tr, te], [yA - hgt / 2, yE + hgt / 2], color=CORAL, linewidth=0.6,
                    linestyle=(0, (1.5, 1.2)))
    # stamps between the lanes
    for t, w in stamps:
        ax.plot([t, t], [yE + hgt / 2 + 0.04, yA - hgt / 2 - 0.04], color=INK,
                linewidth=0.9 if w == 'jr' else 0.7, linestyle='-' if w == 'jr' else (0, (2, 1.2)))
    ax.set_xlim(-1, total + 1); ax.set_ylim(yE - hgt - 0.30, yA + hgt + 0.22)
    ax.set_yticks([yE, yA]); ax.set_yticklabels(['emulated', 'accurate'])
    ax.tick_params(axis='y', length=0)
    ax.spines[['top', 'right', 'left']].set_visible(False)
    ax.set_xlabel('Cycles within one inner-loop iteration', labelpad=2)
    h = [Line2D([], [], color=INK, linewidth=0.9, label='stamp at jr'),
         Line2D([], [], color=INK, linewidth=0.7, linestyle=(0, (2, 1.2)), label='stamp at 6th branch'),
         Line2D([], [], color=CORAL, linewidth=1.0, label='guard beq (no stamp)')]
    fig.legend(handles=h, loc='lower center', bbox_to_anchor=(0.55, -0.01), ncol=3, frameon=False,
               handlelength=1.6, handletextpad=0.4, columnspacing=1.0)
    save(fig, out)
    plt.close(fig)
    print(f'wrote {out}.pdf/.png')


if __name__ == '__main__':
    main()
