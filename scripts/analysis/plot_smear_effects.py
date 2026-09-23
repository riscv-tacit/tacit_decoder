#!/usr/bin/env python3
"""Two figures on what a sparse-timestamp clock does to the dispatch profile.

Both use per-predecessor latency histograms of arrivals into one handler, from the same
decode under two clocks: tacit's per-event timestamps (reference) and the TNT+CYC emulation
(sparse), which stamps only uninferable jumps and spreads the elapsed cycles evenly over the
un-stamped events in between.

  entry   Rows = target handlers. Columns: entry block on the reference clock, entry block
          on the sparse clock, whole-handler span on both clocks. Reads left to right: what
          tacit sees, what the sparse clock sees, and why -- the jr-to-jr total is identical
          on both clocks, so the sparse entry-block numbers are that total spread thin.

  span    Rows = interpreter arms (unguarded, one guard). Columns = predecessors of MUL.
          Each panel: whole-handler span, reference filled vs sparse outlined. Row 1 the
          outline sits on the fill; row 2 the guarded MUL->MUL arrival is a `beq`, so its
          boundary is unstamped and the cycles slide onto the neighbouring edges. A strip
          above each row shows which boundaries carry a stamp.

  plot_smear_effects.py entry --optab O --entry-ref H --entry-emu H --span-ref H --span-emu H \
      --targets MUL,ADD --out fig.smear_entry
  plot_smear_effects.py span --target MUL --preds MUL,LTI,LEI,MULK --out fig.smear_span \
      "unguarded=ref.csv:emu.csv:optab.json" "+MUL->MUL=ref.csv:emu.csv:optab.json:2" \
      "+MUL->ADD=ref.csv:emu.csv:optab.json:2+3"
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
from matplotlib.patches import Patch
from matplotlib.lines import Line2D

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from paper_palette import (MM, CATEGORICAL, NEUTRAL, NAVY, CORAL, CYAN, INK, INK2, GRID,
                           tint, style, fit_tight, save)


# ------------------------------------------------------------------ data
def load_hist(csv, optab_path):
    """-> {(from_op, to_op): Series cycles -> count}, aggregated BY OPCODE so that two
    addresses naming the same handler (a guarded entry copy aliased to its opcode) add up
    instead of overwriting each other."""
    tab = {int(k, 16): v for k, v in json.load(open(optab_path)).items()}
    d = pd.read_csv(csv)
    for c in ('from_handler', 'to_handler'):
        d[c] = d[c].map(lambda s: tab.get(int(str(s).strip(), 16)))
    d = d.dropna(subset=['from_handler', 'to_handler'])
    out = {}
    for (f, t), g in d.groupby(['from_handler', 'to_handler']):
        out[(f, t)] = g.groupby('cycles')['count'].sum().sort_index()
    return out


def into(h, target):
    """{pred: Series} for arrivals into `target`."""
    return {f: s for (f, t), s in h.items() if t == target}


def mean_of(s):
    return float((s.index.to_numpy(float) * s.to_numpy(float)).sum() / s.sum())


def dense(s, xmax):
    y = np.zeros(xmax + 1)
    c = s.index.to_numpy(int)
    m = (c >= 0) & (c <= xmax)
    np.add.at(y, c[m], s.to_numpy(float)[m])
    return y


def xmax_for(series_list, coverage=0.995):
    c = np.concatenate([s.index.to_numpy(float) for s in series_list])
    w = np.concatenate([s.to_numpy(float) for s in series_list])
    o = np.argsort(c)
    cdf = np.cumsum(w[o]) / w.sum()
    return int(c[o][np.searchsorted(cdf, coverage)]) + 2


def cycle_axis(ax, xmax, st, grid=True):
    ax.set_xlim(0, xmax + 0.5)
    ax.set_xticks(np.arange(0, xmax + 1, 5))
    ax.set_xticks(np.arange(0, xmax + 1), minor=True)
    ax.tick_params(axis='x', which='minor', length=1.3, width=0.4)
    ax.spines[['top', 'right']].set_visible(False)
    ax.set_axisbelow(True)
    if grid:
        ax.xaxis.grid(True, which='major', color=GRID, linewidth=st['grid_lw'])
        ax.yaxis.grid(True, color=GRID, linewidth=st['grid_lw'])


def step_outline(ax, y, color, lw=0.9, ls='-', z=5):
    """Histogram outline: horizontal segment across each bin, drawn as a step."""
    x = np.arange(len(y) + 1) - 0.5
    ax.step(x, np.append(y, y[-1]), where='post', color=color, linewidth=lw,
            linestyle=ls, zorder=z, solid_joinstyle='miter')


def run_outline(ax, y, color, lw=0.9, z=5):
    """Histogram outline drawn only where there is mass: each contiguous run of non-zero
    bins becomes one closed step path that rises from the axis at its left edge and returns
    to it at its right edge, so every mode is a closed box and nothing runs along zero."""
    nz = np.flatnonzero(y > 0)
    if len(nz) == 0:
        return
    breaks = np.flatnonzero(np.diff(nz) > 1) + 1
    for run in np.split(nz, breaks):
        xs, ys = [run[0] - 0.5], [0.0]
        for c in run:
            xs += [c - 0.5, c + 0.5]
            ys += [y[c], y[c]]
        xs.append(run[-1] + 0.5); ys.append(0.0)
        ax.plot(xs, ys, color=color, linewidth=lw, zorder=z, solid_joinstyle='miter',
                solid_capstyle='projecting')


# ------------------------------------------------------------------ figure 1
def fig_entry(a):
    st = style(venue=a.venue)
    width = st['double']
    ER, EE = load_hist(a.entry_ref, a.optab), load_hist(a.entry_emu, a.optab)
    SR, SE = load_hist(a.span_ref, a.optab), load_hist(a.span_emu, a.optab)
    targets = [t.strip() for t in a.targets.split(',')]

    # colour by predecessor identity, shared across rows (as plot_pred_grid does)
    ranked, rows_of = {}, {}
    for t in targets:
        ctx = into(ER, t)
        n = sum(s.sum() for s in ctx.values())
        ranked[t] = [p for p in sorted(ctx, key=lambda p: -ctx[p].sum())
                     if ctx[p].sum() / n >= a.min_share]
        for p in ranked[t]:
            rows_of.setdefault(p, []).append(t)
    shared = sorted((p for p, rs in rows_of.items() if len(rs) > 1), key=lambda p: -len(rows_of[p]))
    glob = {p: CATEGORICAL[i] for i, p in enumerate(shared) if i < len(CATEGORICAL)}
    keys = {}
    for t in targets:
        key = dict((p, glob[p]) for p in ranked[t] if p in glob)
        for p in ranked[t]:
            if p not in key:
                free = [c for c in CATEGORICAL if c not in key.values()]
                if free:
                    key[p] = free[0]
        keys[t] = key

    nr, nc = len(targets), 3
    mpl.rcParams.update({'figure.constrained_layout.use': True,
                         'figure.constrained_layout.hspace': 0.08,
                         'figure.constrained_layout.wspace': 0.04,
                         'figure.constrained_layout.h_pad': 0.02,
                         'figure.constrained_layout.w_pad': 0.02})
    fig, axes = plt.subplots(nr, nc, figsize=(width * MM, nr * a.row_height * MM), squeeze=False)
    titles = ['Entry block, reference clock', 'Entry block, sparse clock',
              'Whole handler (jr to jr), both clocks']

    for r, t in enumerate(targets):
        key = keys[t]
        ctx_r, ctx_e = into(ER, t), into(EE, t)
        sp_r, sp_e = into(SR, t), into(SE, t)
        denom = sum(s.sum() for s in ctx_r.values())
        xmax_entry = xmax_for(list(ctx_r.values()) + list(ctx_e.values()), a.coverage)
        xmax_span = xmax_for(list(sp_r.values()) + list(sp_e.values()), a.coverage)
        order = list(key) + [p for p in ctx_r if p not in key]

        def stacked(ax, ctx, xmax):
            bottom = np.zeros(xmax + 1)
            for p in order:
                if p not in ctx:
                    continue
                y = 100 * dense(ctx[p], xmax) / denom
                ax.bar(np.arange(xmax + 1), y, bottom=bottom, width=1.0,
                       color=key.get(p, NEUTRAL), edgecolor='white', linewidth=0.2, zorder=3)
                bottom += y
            return bottom

        tops = []
        for c, (ctx, xmax) in enumerate([(ctx_r, xmax_entry), (ctx_e, xmax_entry)]):
            ax = axes[r][c]
            tops.append(stacked(ax, ctx, xmax).max())
            cycle_axis(ax, xmax, st)
        # column 3: reference stacked, sparse total as an outline on top of the stack
        ax = axes[r][2]
        top = stacked(ax, sp_r, xmax_span)
        tot_e = 100 * sum(dense(s, xmax_span) for s in sp_e.values()) / denom
        step_outline(ax, tot_e, INK, lw=0.8)
        cycle_axis(ax, xmax_span, st)
        tops.append(max(top.max(), tot_e.max()))

        ymax = max(tops[:2]) * 1.15
        for c in range(2):
            axes[r][c].set_ylim(0, ymax)
        axes[r][2].set_ylim(0, tops[2] * 1.2)

        for c in range(nc):
            ax = axes[r][c]
            if r == 0:
                ax.set_title(titles[c], color=INK, pad=3)
            if c == 0:
                ax.set_ylabel(f'Arrivals into {t}\n(% of {denom/1e6:.1f}M instances)')
            if r == nr - 1:
                ax.set_xlabel('Latency (cycles)' if c < 2 else 'Handler span (cycles)')
            else:
                ax.tick_params(labelbottom=False)
            ax.text(-0.04, 1.12, 'abcdefghi'[r * nc + c], transform=ax.transAxes,
                    fontsize=st['panel'], fontweight='bold', va='top', ha='left')

        # legend: predecessor, with its mean under each clock (entry block) -- direct
        # numbers instead of a fourth plot; placed in the sparse panel where there is room
        h = []
        for p, col in key.items():
            mr = mean_of(ctx_r[p]) if p in ctx_r else float('nan')
            me = mean_of(ctx_e[p]) if p in ctx_e else float('nan')
            h.append(Patch(facecolor=col, edgecolor='white', linewidth=0.3,
                           label=f'after {p}   {mr:4.1f} → {me:3.1f}'))
        if any(p not in key for p in ctx_r):
            h.append(Patch(facecolor=NEUTRAL, edgecolor='white', linewidth=0.3, label='other'))
        axes[r][1].legend(handles=h, loc='upper right', frameon=False, handlelength=1.2,
                          handletextpad=0.4, labelspacing=0.3,
                          title='mean, reference → sparse', title_fontsize=st['tick'])
        # column 3 key
        h3 = [Patch(facecolor=tint(NAVY, 0.5), edgecolor='white', label='reference'),
              Line2D([], [], color=INK, linewidth=0.8, label='sparse, total')]
        axes[r][2].legend(handles=h3, loc='upper left', frameon=False, handlelength=1.4,
                          handletextpad=0.4, labelspacing=0.3)

    fit_tight(fig, width, nr * a.row_height)
    save(fig, a.out)
    plt.close(fig)
    print(f'wrote {a.out}.pdf/.png')


# ------------------------------------------------------------------ figure 2
def parse_arm(spec):
    """LABEL=REF:EMU:OPTAB[:UNSTAMPED]  -- UNSTAMPED lists boundary indices of the
    LEI|MUL|MUL|ADD schematic that carry no stamp (guarded `beq`), e.g. "2" or "2+3"."""
    label, _, rest = spec.partition('=')
    parts = rest.split(':')
    ref, emu, optab = parts[:3]
    unstamped = {int(x) for x in parts[3].split('+')} if len(parts) > 3 and parts[3] else set()
    return label, ref, emu, optab, unstamped


def fig_span(a):
    st = style(venue=a.venue)
    width = st['double']
    arms = [parse_arm(s) for s in a.arms]
    preds = [p.strip() for p in a.preds.split(',')]
    data = []
    for label, ref, emu, optab, unstamped in arms:
        R, E = load_hist(ref, optab), load_hist(emu, optab)
        data.append((label, into(R, a.target), into(E, a.target), unstamped))
    xmax = xmax_for([s for _, r, e, _u in data for d in (r, e) for p, s in d.items() if p in preds],
                    a.coverage)

    nr, nc = len(arms), len(preds)
    # explicit layout: the row label and the conservation note overhang their panels, and
    # constrained layout would reserve width for that overhang and squeeze the panels
    mpl.rcParams.update({'figure.constrained_layout.use': False})
    height = nr * a.row_height
    fig = plt.figure(figsize=(width * MM, height * MM))
    gs = fig.add_gridspec(nr, nc, left=0.07, right=0.995, top=0.90, bottom=0.14,
                          hspace=0.95, wspace=0.28)
    for r, (label, ctx_r, ctx_e, unstamped) in enumerate(data):

        shift_terms = []
        ymax = 0
        panels = []
        for c, p in enumerate(preds):
            ax = fig.add_subplot(gs[r, c])
            panels.append(ax)
            if p not in ctx_r:
                ax.text(0.5, 0.5, f'no {p} arrivals', transform=ax.transAxes, ha='center',
                        va='center', color=INK2)
                cycle_axis(ax, xmax, st)
                continue
            n = ctx_r[p].sum()
            yr = 100 * dense(ctx_r[p], xmax) / n
            ye = 100 * dense(ctx_e[p], xmax) / n
            ax.bar(np.arange(xmax + 1), yr, width=1.0, color=tint(NAVY, 0.45),
                   edgecolor='white', linewidth=0.2, zorder=3)
            step_outline(ax, ye, CORAL, lw=1.0)
            cycle_axis(ax, xmax, st)
            mr, me = mean_of(ctx_r[p]), mean_of(ctx_e[p])
            shift_terms.append((p, n, me - mr))
            ymax = max(ymax, yr.max(), ye.max())
            tag = f'{p} → {a.target}'
            if 2 in unstamped and p == a.target:
                tag += '  (via guard)'
            ax.set_title(tag, color=INK, pad=2, fontsize=st['base'])
            ax.text(0.97, 0.94, f'{n/1e6:.1f}M\nmean {mr:.1f} → {me:.1f}',
                    transform=ax.transAxes, ha='right', va='top', fontsize=st['tick'],
                    color=INK2, linespacing=1.15)
            if c == 0:
                ax.set_ylabel('Arrivals (% of edge)')
            if r == nr - 1:
                ax.set_xlabel('Handler span (cycles)')
            else:
                ax.tick_params(labelbottom=False)
        for ax in panels:
            ax.set_ylim(0, ymax * 1.6)
        # traffic-weighted shift: the cycles the sparse clock moved between edges
        tot = sum(n * d for _, n, d in shift_terms) / 1e6
        parts = '  '.join(f'{p}:{n*d/1e6:+.0f}' for p, n, d in shift_terms if abs(n * d) / 1e6 >= 1)
        msg = (f'sparse − reference, traffic-weighted: {parts} Mcyc,  Σ = {tot:+.0f}'
               if parts else 'sparse − reference: 0 on every edge')
        # row label at the left, conservation note at the right, in FIGURE coordinates
        # just above the row's panel titles
        p0, pl = panels[0].get_position(), panels[-1].get_position()
        ytxt = p0.y1 + 0.135 / nr
        fig.text(p0.x0 - 0.045, ytxt, 'abcdefgh'[r], fontsize=st['panel'], fontweight='bold',
                 va='bottom', ha='left')
        fig.text(p0.x0, ytxt, label, fontsize=st['base'], fontweight='bold', va='bottom',
                 ha='left', color=INK)
        fig.text(pl.x1, ytxt, msg, fontsize=st['tick'], va='bottom', ha='right', color=INK2)


    h = [Patch(facecolor=tint(NAVY, 0.45), edgecolor='white', label='reference clock'),
         Line2D([], [], color=CORAL, linewidth=1.0, label='sparse clock (TNT+CYC, n=6)')]
    fig.legend(handles=h, loc='lower center', bbox_to_anchor=(0.5, 0.0), ncol=2, frameon=False,
               handlelength=1.4, handletextpad=0.4, columnspacing=1.5)

    save(fig, a.out)
    plt.close(fig)
    print(f'wrote {a.out}.pdf/.png')


# ------------------------------------------------------------------ figure 3
def seq_spans(seq_csv, optab_path, f_op, t_op, max_span=200):
    """-> (spans, successor opcode) for every arrival into t_op from f_op, from the
    dispatch_seq stream (entry timestamp, handler). The successor identifies the bytecode
    site when the same edge occurs at several places in a loop."""
    tab = {int(k, 16): v for k, v in json.load(open(optab_path)).items()}
    d = pd.read_csv(seq_csv)
    ts = d['timestamp'].to_numpy(np.int64)
    h = d['to_handler'].map(lambda s: tab.get(int(s, 16), '?')).to_numpy()
    span = np.diff(ts)
    h1, h2, h3 = h[:-2], h[1:-1], h[2:]
    sp = span[1:]
    sel = (h1 == f_op) & (h2 == t_op) & (sp <= max_span)
    return sp[sel], h3[sel]


def fig_sites(a):
    """Rows = arms, columns = clocks. Each panel: the span of `TO` when entered from `FROM`,
    stacked by the handler that follows -- i.e. by bytecode site."""
    st = style(venue=a.venue)
    width = st['double']
    f_op, t_op = [x.strip() for x in a.edge.split(',')]
    names = dict(kv.split('=', 1) for kv in a.site_names.split(';')) if a.site_names else {}
    arms = []
    for spec in a.arms:
        label, _, rest = spec.partition('=')
        ref, emu, optab = rest.split(':')
        arms.append((label, seq_spans(ref, optab, f_op, t_op), seq_spans(emu, optab, f_op, t_op)))
    # the sites, in traffic order over the reference streams; two colours, then neutral
    succ = pd.concat([pd.Series(r[1]) for _, r, _ in arms]).value_counts()
    sites = list(succ.index[:2])
    colour = {sites[0]: NAVY, sites[1] if len(sites) > 1 else None: CORAL}
    allsp = np.concatenate([x[0] for _, r, e in arms for x in (r, e)])
    xmax = int(np.quantile(allsp, a.coverage)) + 2

    nr, nc = len(arms), 2
    mpl.rcParams.update({'figure.constrained_layout.use': True,
                         'figure.constrained_layout.hspace': 0.10,
                         'figure.constrained_layout.wspace': 0.04,
                         'figure.constrained_layout.h_pad': 0.02,
                         'figure.constrained_layout.w_pad': 0.02})
    fig, axes = plt.subplots(nr, nc, figsize=(width * MM, nr * a.row_height * MM), squeeze=False)
    for r, (label, ref, emu) in enumerate(arms):
        n_all = len(ref[0])
        tops = []
        for c, (clk, (sp, nx)) in enumerate((('reference clock', ref), ('sparse clock (TNT+CYC, n=6)', emu))):
            ax = axes[r][c]
            bottom = np.zeros(xmax + 1)
            notes = []
            for site in sites + ['other']:
                m = (nx == site) if site != 'other' else ~np.isin(nx, sites)
                if not m.any():
                    continue
                y = 100 * np.bincount(np.clip(sp[m], 0, xmax), minlength=xmax + 1) / n_all
                ax.bar(np.arange(xmax + 1), y, bottom=bottom, width=1.0,
                       color=colour.get(site, NEUTRAL), edgecolor='white', linewidth=0.2, zorder=3)
                bottom += y
                if site != 'other':
                    notes.append((site, sp[m].mean(), m.sum()))
            cycle_axis(ax, xmax, st)
            tops.append(bottom.max())
            if r == 0:
                ax.set_title(clk, color=INK, pad=3)
            if c == 0:
                ax.set_ylabel(f'{t_op} after {f_op}\n(% of {n_all/1e6:.1f}M arrivals)')
            if r == nr - 1:
                ax.set_xlabel('Handler span (cycles)')
            else:
                ax.tick_params(labelbottom=False)
            ax.text(-0.04, 1.12, 'abcdefghi'[r * nc + c], transform=ax.transAxes,
                    fontsize=st['panel'], fontweight='bold', va='top', ha='left')
            # per-site mean, in the site's colour via a swatch, not coloured text
            h = [Patch(facecolor=colour[sname], edgecolor='white',
                       label=f'{names.get(sname, "then " + sname)}   mean {mu:.1f}')
                 for sname, mu, n in notes]
            ax.legend(handles=h, loc='upper left', frameon=False, handlelength=1.2,
                      handletextpad=0.4, labelspacing=0.3, title=label if c == 0 else None,
                      title_fontsize=st['base'], alignment='left')
        # one y range per row, with room for the legend above the tallest stack
        for ax in axes[r]:
            ax.set_ylim(0, max(tops) * 1.9)
    fit_tight(fig, width, nr * a.row_height)
    save(fig, a.out)
    plt.close(fig)
    print(f'wrote {a.out}.pdf/.png')


# ------------------------------------------------------------------ figure 4
def fig_edge(a):
    """One edge, two panels, single column: (a) the target's entry block on the reference
    clock -- the dispatch cost, nothing else; (b) the whole-handler span, reference filled
    under the sparse outline -- the only dispatch-attributable interval a sparse tracer
    can form, and what it would conclude from it."""
    st = style(venue=a.venue)
    width = st['single']
    f_op, t_op = [x.strip() for x in a.edge.split(',')]

    # (a) entry block: the full-run bb_hist rows of the block that starts at --entry-block.
    # The block must be listed in bb_stats' hist_bbs for that decode; there is deliberately
    # no other source, so the figure cannot silently change provenance.
    bh = pd.read_csv(a.bb_hist, skipinitialspace=True)
    bh['bb'] = bh['bb'].astype(str).str.strip()
    bh['start'] = bh['bb'].str.split('-').str[0].str.lower()
    e = bh[bh.start == a.entry_block.lower()].groupby('cycles')['count'].sum().sort_index()
    if e.empty:
        raise SystemExit(f'{a.entry_block} not in {a.bb_hist}: add it to bb_stats hist_bbs and re-decode')
    # (b) span: dispatch_hist under both clocks
    SR, SE = load_hist(a.span_ref, a.optab), load_hist(a.span_emu, a.optab)
    sr, se = SR[(f_op, t_op)], SE[(f_op, t_op)]
    n_e, n_s = e.sum(), sr.sum()
    xmax = a.xmax or xmax_for([e, sr, se], a.coverage)

    # fixed margins: a legend below the x labels needs its own band, which constrained
    # layout's 'outside' placement does not let us size
    mpl.rcParams.update({'figure.constrained_layout.use': False})
    fig = plt.figure(figsize=(width * MM, a.height * MM))
    gs = fig.add_gridspec(1, 2, left=0.14, right=0.99, top=0.86, bottom=0.34, wspace=0.10)
    axes = [fig.add_subplot(gs[0, 0])]
    axes.append(fig.add_subplot(gs[0, 1], sharey=axes[0]))
    axes[1].tick_params(labelleft=False)

    ax = axes[0]
    ye = 100 * dense(e, xmax) / n_e
    ax.bar(np.arange(xmax + 1), ye, width=1.0, color=tint(NAVY, 0.45), edgecolor='white',
           linewidth=0.2, zorder=3)
    cycle_axis(ax, xmax, st)
    ax.set_title('Entry block', color=INK, pad=4)
    ax.set_ylabel('Share of executions (%)')

    ax = axes[1]
    yr = 100 * dense(sr, xmax) / n_s
    ys = 100 * dense(se, xmax) / n_s
    ax.bar(np.arange(xmax + 1), yr, width=1.0, color=tint(NAVY, 0.45), edgecolor='white',
           linewidth=0.2, zorder=3)
    if a.emu_style in ('fill', 'both'):
        # translucent fill over the reference bars, so both remain readable where they overlap
        ax.bar(np.arange(xmax + 1), ys, width=1.0, color=CORAL, alpha=a.emu_alpha,
               edgecolor='none', zorder=4)
    if a.emu_style in ('outline', 'both'):
        run_outline(ax, ys, CORAL, lw=0.9)
    cycle_axis(ax, xmax, st)
    ax.set_title('Handler span', color=INK, pad=4)

    ymax = max(ye.max(), yr.max(), ys.max()) * 1.15
    for k, ax in enumerate(axes):
        ax.set_ylim(0, ymax)
        ax.set_xlabel('Cycles')
        # panel letter sits left of the title, on the title line
        ax.text(0.0, 1.0, 'ab'[k], transform=ax.transAxes, fontsize=st['panel'],
                fontweight='bold', va='bottom', ha='left')
    # the clock legend goes in (a), whose right half is empty
    if a.emu_style == 'outline':
        emu_handle = Line2D([], [], color=CORAL, linewidth=0.9, label='emulated (TNT+CYC)')
    elif a.emu_style == 'fill':
        emu_handle = Patch(facecolor=CORAL, alpha=a.emu_alpha, edgecolor='none', label='emulated (TNT+CYC)')
    else:
        emu_handle = Patch(facecolor=CORAL, alpha=a.emu_alpha, edgecolor=CORAL, linewidth=0.9,
                           label='emulated (TNT+CYC)')
    h = [Patch(facecolor=tint(NAVY, 0.45), edgecolor='white', label='accurate'), emu_handle]
    # below both panels; constrained layout reserves the space for an 'outside' legend
    fig.legend(handles=h, loc='lower center', bbox_to_anchor=(0.56, 0.0), ncol=2, frameon=False,
               handlelength=1.3, handletextpad=0.4, columnspacing=1.5)
    save(fig, a.out)
    plt.close(fig)
    print(f'wrote {a.out}.pdf/.png')


# ------------------------------------------------------------------ figure 5
def fig_unit(a):
    """One handler, all its hot predecessors, accurate clock, two units side by side: the
    entry block (dispatch cost only) and the whole-handler span (dispatch + body). Stacked by
    predecessor so identity carries across the panels; the selection floor (min median over
    predecessors) is marked in each. Where a predecessor sits at the floor in (a) but well
    above it in (b), the span view reports an opportunity that is body cost."""
    st = style(venue=a.venue, scale=a.font_scale)
    width = st['single']
    E = load_hist(a.entry_hist, a.optab)
    S = load_hist(a.span_hist, a.optab)
    ctx_e = {f: h for (f, t), h in E.items() if t == a.target}
    ctx_s = {f: h for (f, t), h in S.items() if t == a.target}
    n_all = sum(h.sum() for h in ctx_e.values())
    preds = [f for f in sorted(ctx_e, key=lambda f: -ctx_e[f].sum()) if ctx_e[f].sum() / n_all >= a.min_share]
    if a.preds:
        preds = [p for p in a.preds.split(',') if p in ctx_e]
    colour = {f: c for f, c in zip(preds, CATEGORICAL)}
    xmax_e = a.xmax_entry or xmax_for([ctx_e[f] for f in preds], a.coverage)
    xmax_s = a.xmax_span or xmax_for([ctx_s[f] for f in preds], a.coverage)

    def floor_of(ctx):
        # min median over hot predecessors, the selection tool's floor
        meds = []
        for f in preds:
            h = ctx[f]; cdf = h.cumsum() / h.sum()
            meds.append(int(h.index[(cdf >= 0.5).to_numpy().argmax()]))
        return min(meds)

    mpl.rcParams.update({'figure.constrained_layout.use': False})
    fig = plt.figure(figsize=(width * MM, a.height * MM))
    gs = fig.add_gridspec(1, 2, left=0.15, right=0.99, top=0.86, bottom=a.bottom, wspace=0.10)
    axes = [fig.add_subplot(gs[0, 0])]; axes.append(fig.add_subplot(gs[0, 1], sharey=axes[0]))
    axes[1].tick_params(labelleft=False)
    tops = []
    for ax, ctx, xmax, title in ((axes[0], ctx_e, xmax_e, 'Entry block'), (axes[1], ctx_s, xmax_s, 'Handler span')):
        bottom = np.zeros(xmax + 1)
        for f in preds + [f for f in ctx if f not in preds]:
            y = 100 * dense(ctx[f], xmax) / n_all
            ax.bar(np.arange(xmax + 1), y, bottom=bottom, width=1.0, color=colour.get(f, NEUTRAL),
                   edgecolor='white', linewidth=0.2, zorder=3)
            bottom += y
        tops.append(bottom.max())
        fl = floor_of(ctx)
        ax.axvline(fl, color=INK2, linewidth=0.8, linestyle=(0, (2.5, 1.5)), zorder=4)
        cycle_axis(ax, xmax, st)
        ax.set_title(title, color=INK, pad=4)
        ax.set_xlabel('Cycles')
    axes[0].set_ylabel('Arrivals (%)')
    for k, ax in enumerate(axes):
        ax.set_ylim(0, max(tops) * 1.18)
        ax.text(0.0, 1.0, 'ab'[k], transform=ax.transAxes, fontsize=st['panel'], fontweight='bold',
                va='bottom', ha='left')
    h = [Patch(facecolor=colour[f], edgecolor='white', label=f'after {f}') for f in preds]
    if any(f not in preds for f in ctx_e):
        h.append(Patch(facecolor=NEUTRAL, edgecolor='white', label='other'))
    h.append(Line2D([], [], color=INK2, linewidth=0.8, linestyle=(0, (2.5, 1.5)), label='floor'))
    fig.legend(handles=h, loc='lower center', bbox_to_anchor=(0.57, 0.0), ncol=a.legend_cols, frameon=False,
               handlelength=1.3, handletextpad=0.4, columnspacing=1.2, labelspacing=0.35)
    save(fig, a.out)
    plt.close(fig)
    fe, fs = floor_of(ctx_e), floor_of(ctx_s)
    print(f'{a.target}: floor entry {fe}, span {fs}')
    for f in preds:
        me, ms = mean_of(ctx_e[f]), mean_of(ctx_s[f])
        print(f'  after {f:6s} n={ctx_e[f].sum()/1e6:5.1f}M  entry {me:5.2f} (+{me-fe:4.1f} over floor)   span {ms:5.2f} (+{ms-fs:4.1f} over floor)   body {ms-me:5.2f}')
    print(f'wrote {a.out}.pdf/.png')


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    e = sub.add_parser('entry')
    e.add_argument('--optab', required=True)
    e.add_argument('--entry-ref', required=True); e.add_argument('--entry-emu', required=True)
    e.add_argument('--span-ref', required=True);  e.add_argument('--span-emu', required=True)
    e.add_argument('--targets', default='MUL,ADD')
    e.add_argument('--min-share', type=float, default=0.01)
    e.add_argument('--coverage', type=float, default=0.995)
    e.add_argument('--row-height', type=float, default=46.0)
    e.add_argument('--venue', default='acm')
    e.add_argument('--out', required=True)
    e.set_defaults(fn=fig_entry)
    s = sub.add_parser('span')
    s.add_argument('arms', nargs='+', metavar='LABEL=REF:EMU:OPTAB')
    s.add_argument('--target', default='MUL')
    s.add_argument('--preds', default='MUL,LTI,LEI,MULK')
    s.add_argument('--coverage', type=float, default=0.995)
    s.add_argument('--row-height', type=float, default=40.0)
    s.add_argument('--venue', default='acm')
    s.add_argument('--out', required=True)
    s.set_defaults(fn=fig_span)
    t = sub.add_parser('sites')
    t.add_argument('arms', nargs='+', metavar='LABEL=REFSEQ:EMUSEQ:OPTAB')
    t.add_argument('--edge', default='MUL,MUL', help='FROM,TO opcode names')
    t.add_argument('--site-names', default='', help='"ADD=pc 40, then ADD;SUB=pc 48, then SUB"')
    t.add_argument('--coverage', type=float, default=0.995)
    t.add_argument('--row-height', type=float, default=34.0)
    t.add_argument('--venue', default='acm')
    t.add_argument('--out', required=True)
    t.set_defaults(fn=fig_sites)
    g = sub.add_parser('edge')
    g.add_argument('--optab', required=True)
    g.add_argument('--edge', default='MUL,MUL')
    g.add_argument('--bb-hist', required=True, help='reference bb_hist (full run) containing the entry block')
    g.add_argument('--entry-block', required=True, help='start address of the target entry block for this edge')
    g.add_argument('--span-ref', required=True); g.add_argument('--span-emu', required=True)
    g.add_argument('--coverage', type=float, default=0.995)
    g.add_argument('--xmax', type=int, default=0)
    g.add_argument('--emu-style', default='both', choices=('fill', 'outline', 'both'))
    g.add_argument('--emu-alpha', type=float, default=0.55)
    g.add_argument('--height', type=float, default=40.0)
    g.add_argument('--venue', default='acm')
    g.add_argument('--out', required=True)
    g.set_defaults(fn=fig_edge)
    u = sub.add_parser('unit')
    u.add_argument('--optab', required=True)
    u.add_argument('--entry-hist', required=True, help='dispatch_hist, entry unit, accurate clock')
    u.add_argument('--span-hist', required=True, help='dispatch_hist, span unit, accurate clock')
    u.add_argument('--target', required=True, help='the handler whose arrivals are shown')
    u.add_argument('--preds', help='comma-separated predecessors to show (default: all with >= --min-share)')
    u.add_argument('--min-share', type=float, default=0.01)
    u.add_argument('--xmax-entry', type=int, default=0); u.add_argument('--xmax-span', type=int, default=0)
    u.add_argument('--coverage', type=float, default=0.995)
    u.add_argument('--height', type=float, default=52.0)
    u.add_argument('--bottom', type=float, default=0.42, help='figure fraction reserved below the axes for x labels + legend')
    u.add_argument('--font-scale', type=float, default=1.25, help='text size multiplier over the venue base (single-column figures read small at 1.0)')
    u.add_argument('--legend-cols', type=int, default=3)
    u.add_argument('--venue', default='acm')
    u.add_argument('--out', required=True)
    u.set_defaults(fn=fig_unit)
    a = ap.parse_args()
    a.fn(a)


if __name__ == '__main__':
    main()
