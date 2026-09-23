#!/usr/bin/env python3
"""
fig.b7_pipeline.png -- why block B7 measures 5 cycles or 11 cycles.

Two panels over the same 35-cycle window, one fixed 14-cycle dependency chain
(BOOM v3).  The measured "block latency" is commit(beqz) - commit(j): the right
end is pinned by the chain, the left end moves with whether commit is backed up.

  panel a: jr a5 predicted correctly -> fetch runs ahead, commit is saturated
           -> T1 = commit(j) is drain-limited at W+9 -> 5 cycles
  panel b: jr a5 mispredicts        -> commit runs dry
           -> T1 = commit(j) lands at W+3 (= R+21) -> 11 cycles

NB the squash is PARTIAL: only uops younger than the mispredicted jr are
killed (rob.scala:472-482), and older ones keep committing. What is fully
cleared is the FRONTEND -- F1-F4, fetch buffer, FTQ enq (frontend.scala:965-981).
Commit runs dry not because the ROB was emptied but because the ~10-cycle
refetch is longer than the ~5 cycles needed to drain what was older.

Timebase: both panels are labelled relative to W, the cycle fld fa5 writes
back, so the chain occupies the same columns in both.  In panel b the redirect
cycle R sits at W-18 and is marked; panel b's event cycles in R terms are in
the callouts.

Drawn with the bagpype DSL (/scratch/iansseijelly/bagpype), which is read-only
here: the two panels are two Pipelines rendered to two figures and stacked.

run:  /scratch/iansseijelly/tacit-chipyard/.conda-env/bin/python3 draw_b7_pipeline.py
"""
import os
import sys
import types

BAGPYPE_SRC = "/scratch/iansseijelly/bagpype/src"
OUTDIR = "/scratch/iansseijelly/tacit-chipyard/software/tacit_decoder/output_mulmul_mandelbrot"
TMPDIR = "/tmp"

sys.path.insert(0, BAGPYPE_SRC)

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# bagpype imports seaborn only for sns.set_style(); this conda env has no
# seaborn, so stub it out with the equivalent matplotlib style.
if "seaborn" not in sys.modules:
    _sns = types.ModuleType("seaborn")

    def _set_style(style="whitegrid", rc=None):
        try:
            plt.style.use("seaborn-v0_8-" + style)
        except Exception:
            pass
        if rc:
            plt.rcParams.update(rc)

    _sns.set_style = _set_style
    sys.modules["seaborn"] = _sns

import bagpype as bp                                    # noqa: E402
from bagpype.visualization import RenderConfig           # noqa: E402
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Patch  # noqa: E402
from matplotlib.lines import Line2D                      # noqa: E402

# ---------------------------------------------------------------- palette ----
NAVY = "#3c5488"
RED = "#e64b35"
TEAL = "#00786a"
VIOLET = "#6a4c93"
GREY = "#8a8a8a"
GOLD_E = "#8f6410"

CHAIN = "#c4ccdb"        # fixed FP dependency chain
CHAIN_D = "#a7b2c9"      # the multiply itself
UOP = "#f8cdc6"          # the second, internal store-data micro-op
COMMIT = "#e4e4e4"       # in-order ROB row commit
TS = "#ffd45e"           # the two timestamps the trace hardware records
BAND = "#fafafa"         # "finished / ready, waiting for its commit slot"
FRONT = "#ddd0e8"        # frontend refetch F0..F4 + decode
MISP = "#f4a49a"         # the redirect cycle
PRED = "#a8ded4"         # the same jr, correctly predicted
DISP = "#ffffff"         # dispatch into the ROB

BAND_STYLE = bp.NodeStyle(color=BAND, linestyle="--")

# --------------------------------------------------------------- geometry ----
XMIN, XMAX = -20, 14            # 35 columns; W == 0, R == -18
NCOL = XMAX - XMIN + 1
FIG_W = 19.5
LEFT_IN = 3.30
RIGHT_IN = 0.25
PITCH_Y = 0.52                  # inches per row; identical in both panels
IU = (FIG_W - LEFT_IN - RIGHT_IN) / NCOL          # inches per x data unit
X_LBL = XMIN - 0.5 - 2.72 / IU                    # instruction label column
X_SEC = XMIN - 0.5 - 3.16 / IU                    # rotated section label
FONT = "DejaVu Sans Mono"
SANS = "DejaVu Sans"
R = -18                         # the redirect cycle, in W-relative units

SECTIONS = [
    (0, 3, "ITERATION k-1", "#f4f4f4"),
    (4, 4, "FRONTEND", "#f3ecf9"),
    (5, 11, "ITERATION k -- CORRECT PATH", "#fbfbfb"),
    (12, 14, "THE 14-CYCLE CHAIN", "#e8f0fa"),
    (15, 16, "ITERATION k", "#fbfbfb"),
]


def callout(ax, text, tx, ty, xy=None, color="black", ha="left", rad=-0.2,
            axy=None, fontsize=9, weight="normal"):
    """Boxed annotation text plus a separate leader arrow (bagpype's grid and
    guide lines would otherwise run straight through the label)."""
    ax.text(tx, ty, text, ha=ha, va="center", fontsize=fontsize, color=color,
            family=SANS, zorder=7, fontweight=weight,
            bbox=dict(fc="white", ec="none", alpha=0.92,
                      boxstyle="round,pad=0.25"))
    if xy is not None:
        ax.annotate("", xy=xy, xytext=(axy if axy else (tx, ty)), zorder=7,
                    arrowprops=dict(arrowstyle="-|>", color=color, lw=1.4,
                                    shrinkA=6, shrinkB=3,
                                    connectionstyle="arc3,rad=%g" % rad))


def band(op, start, dur, text):
    op.add_node(bp.Node(text, start, dur, BAND_STYLE))
    return op.nodes[text]


def box(op, label, t, color, dur=1):
    op.add_node(bp.Node(label, t, dur, bp.NodeStyle(color=color)))
    return op.nodes[label]


# ------------------------------------------------------------------- model ---
# commit cycle of every ROB row, W-relative.  Panel b's numbers are the
# derived R+n schedule (R = W-18); panel a is the same code with commit
# saturated, so the drain staircase runs right up to T1.
COM = {
    "b": {"H'": -16, "I'": -15, "J'": -14, "K'": -13,
          "A": -8, "B": -7, "C": -6, "D": -5,
          "E": 1, "F": 2, "G01": 3, "G23": 8, "H": 13, "I": 14},
    "a": {"H'": -1, "I'": 0, "J'": 1, "K'": 2,
          "A": 3, "B": 4, "C": 5, "D": 6,
          "E": 7, "F": 8, "G01": 9, "G23": 10, "H": 13, "I": 14},
}
DIS = {"A": -12, "B": -11, "C": -10, "D": -9, "E": -8, "F": -7, "G": -5}


def build(panel):
    """Build one panel. panel in {'a','b'}. Returns (pipeline, info)."""
    B = panel == "b"
    com = COM[panel]
    p = bp.Pipeline()
    ops = []
    r = {}                                    # short name -> Op

    def row(key, label):
        o = bp.Op(label)
        ops.append(o)
        r[key] = o
        return o

    # ---- section 1: iteration k-1 tail, the rows older than the branch ----
    for key, label, cap in (
            ("H'", "row H'  sb mv addi fsd", "still going"),
            ("I'", "row I'  beqz lw li andi", "waiting to commit"),
            ("J'", "row J'  beq slli add ld", "waiting to commit")):
        o = row(key, label)
        if not B:
            cap = ("finished long ago -- waiting for a commit slot"
                   if key == "H'" else "")
        band(o, XMIN, com[key] - XMIN, cap)
        box(o, "COM", com[key], COMMIT)

    k = row("K'", "row K'  mv  jr a5")
    box(k, "EX", R - 1, CHAIN)
    if B:
        box(k, "b2", R, MISP)
        band(k, R + 1, com["K'"] - R - 1, "draining")
    else:
        box(k, "ok", R, PRED)
        band(k, R + 1, com["K'"] - R - 1, "")
    box(k, "COM", com["K'"], COMMIT)

    # ---- section 2: the frontend ------------------------------------------
    f = row("FR", "  frontend")
    if B:
        for i, lbl in enumerate(("F0", "F1", "F2", "F3", "F4", "DEC")):
            box(f, lbl, R + i, FRONT)
    else:
        band(f, XMIN, NCOL,
             "fetch never stops -- the frontend runs far ahead of commit")

    # ---- section 3: iteration k, the correct path -------------------------
    ROWS_K = [("A", "row A   srliw zext.b slli"),
              ("B", "row B   add a4"),
              ("C", "row C   lbu srliw srliw zext.b"),
              ("D", "row D   slli slli add add"),
              ("E", "row E   bne li addi beq"),
              ("F", "row F   lbu fld fa4 bne j"),
              ("G", "row G   fld fa5, j | fmul, li")]
    for key, label in ROWS_K:
        o = row(key, label)
        ckey = "G01" if key == "G" else key
        if B:
            box(o, "DIS", DIS[key], DISP)
            cap = "done" if key in "ABCD" else "waiting to commit"
            band(o, DIS[key] + 1, com[ckey] - DIS[key] - 1, cap)
        else:
            band(o, XMIN, com[ckey] - XMIN,
                 "dispatched early, finished -- waiting for a commit slot"
                 if key == "A" else "")
        box(o, "COM", com[ckey], TS if key == "G" else COMMIT)
    g = r["G"]
    if B:
        band(g, com["G01"] + 1, com["G23"] - com["G01"] - 1, "b2-3 wait")
    box(g, "COMb", com["G23"], COMMIT)

    # ---- section 4: the fixed chain (identical in both panels) ------------
    fld = row("fld", "  G.b0  fld    fa5,0(a3)")
    band(fld, -4, 4, "issue/agen/D$")
    box(fld, "WB", 0, CHAIN)

    fmul = row("fmul", "  G.b2  fmul.d fa5,fa5,fa4")
    for lbl, t in (("ISS", 1), ("RRD", 2), ("REQ", 3)):
        box(fmul, lbl, t, CHAIN)
    box(fmul, "FMUL 4c -> WB", 4, CHAIN_D, dur=4)

    fsd = row("fsd", "  H.b3  fsd    fa5,0(a5)")
    for lbl, t in (("ISS", 8), ("RRD", 9), ("SDQ", 10), ("LSU", 11)):
        box(fsd, lbl, t, UOP)
    box(fsd, "CLR", 12, CHAIN)

    # ---- section 5: iteration k tail -------------------------------------
    h = row("H", "row H   sb mv addi fsd")
    hb = 9 if B else 11
    band(h, hb, com["H"] - hb, "at head")
    box(h, "COM", com["H"], COMMIT)

    i = row("I", "row I   beqz lw li andi")
    band(i, hb, com["I"] - hb, "resolved long ago")
    box(i, "COM", com["I"], TS)

    for o in ops:
        p += o

    # ---- edges ------------------------------------------------------------
    dep = bp.EdgeStyle(color=NAVY)
    ino = bp.EdgeStyle(color=GREY)

    if B:
        p += bp.Edge(k.EX >> k.b2, bp.EdgeStyle(color=RED))
        p += bp.Edge(k.b2 >> f.F0, bp.EdgeStyle(color=RED))
        p += bp.Edge(f.DEC >> r["A"].DIS, bp.EdgeStyle(color=VIOLET))
        p += bp.Edge([r[x].DIS for x, _ in ROWS_K], ino)
        p += bp.Edge([r[x].COM for x in ("H'", "I'", "J'", "K'")], ino)
        p += bp.Edge([r[x].COM for x in ("A", "B", "C", "D")], ino)
        p += bp.Edge([r[x].COM for x in ("E", "F", "G")], ino)
    else:
        p += bp.Edge(k.EX >> k.ok, bp.EdgeStyle(color=TEAL))
        p += bp.Edge([r[x].COM for x in
                      ("H'", "I'", "J'", "K'", "A", "B", "C", "D", "E", "F",
                       "G")], ino)

    p += bp.Edge(fld.WB >> fmul.ISS, dep)
    p += bp.Edge(fmul.nodes["FMUL 4c -> WB"] >> fsd.nodes["ISS"], dep)
    p += bp.Edge(fsd.nodes["LSU"] >> fsd.CLR >> h.COM, dep)
    p += bp.Edge(h.COM >> i.COM, bp.EdgeStyle(color=GREY))

    info = dict(ops=ops, nrows=len(ops), r=r, com=com,
                y=lambda o: len(ops) - ops.index(o))
    return p, info


# ------------------------------------------------------------------ render ---
def render(panel):
    B = panel == "b"
    p, info = build(panel)
    n = info["nrows"]
    ytop = 3.15 if B else 2.05
    ax_h = PITCH_Y * (n + ytop - 0.5)
    top_in = 0.72 if B else 1.20
    bot_in = 1.55 if B else 0.50
    fig_h = ax_h + top_in + bot_in

    p.renderer.config = RenderConfig(
        figsize=(FIG_W, fig_h), font_size=9, y_label_font_size=9.5,
        font_family=FONT, edge_routing="curved")

    tmp = os.path.join(TMPDIR, "_bagpype_panel_%s.png" % panel)
    fig, ax = p.draw(save=True, filename=tmp)
    if os.path.exists(tmp):
        os.remove(tmp)

    fig.set_layout_engine("none")
    fig.subplots_adjust(left=LEFT_IN / FIG_W, right=1 - RIGHT_IN / FIG_W,
                        bottom=bot_in / fig_h, top=1 - top_in / fig_h)
    ax.set_ylim(0.5, n + ytop)
    ax.set_xlim(XMIN - 0.5, XMAX + 0.5)

    ops, r, com, y = info["ops"], info["r"], info["com"], info["y"]
    flat = [(o, nd) for o in ops for nd in o.nodes.values()]
    boxes = [q for q in ax.patches if isinstance(q, FancyBboxPatch)]
    arrows = [q for q in ax.patches if isinstance(q, FancyArrowPatch)]
    ntxt = ax.texts[:len(flat)]
    ylab = ax.texts[len(flat):len(flat) + n]
    xlab = ax.texts[len(flat) + n:]
    assert len(boxes) == len(flat), (len(boxes), len(flat))

    # ---- section shading, separators and rotated section labels ----------
    for first, last, name, shade in SECTIONS:
        y0, y1 = n - last - 0.5, n - first + 0.5
        ax.axhspan(y0, y1, color=shade, zorder=0.1, lw=0)
        ax.plot([X_SEC, XMAX + 0.5], [y1, y1], color="#c8c8c8", lw=0.8,
                zorder=0.2, clip_on=False)
        ax.text(X_SEC, (y0 + y1) / 2, name, rotation=90, ha="center",
                va="center", fontsize=8, color="#707070", family=SANS,
                clip_on=False)
    ax.plot([X_SEC, XMAX + 0.5], [0.5, 0.5], color="#c8c8c8", lw=0.8,
            zorder=0.2, clip_on=False)

    # ---- node styling ----------------------------------------------------
    for b in boxes:
        b.set_alpha(1.0)
        b.set_edgecolor("#4a4a4a")
        b.set_zorder(2)
    for a in arrows:
        a.set_alpha(0.95)
        a.set_linewidth(1.6)
        a.set_zorder(4)

    for b, (o, nd) in zip(boxes, flat):
        c = nd.style.color
        if c == TS:
            b.set_edgecolor(GOLD_E)
            b.set_linewidth(2.4)
            b.set_zorder(3)
        elif c == MISP:
            b.set_edgecolor(RED)
            b.set_linewidth(2.4)
            b.set_zorder(3)
        elif c == PRED:
            b.set_edgecolor(TEAL)
            b.set_linewidth(2.4)
            b.set_zorder(3)
        elif c == FRONT:
            b.set_edgecolor(VIOLET)
        elif c == BAND:
            b.set_edgecolor("#c9c9c9")
            b.set_linewidth(1.0)
            b.set_zorder(0.4)

    for t, (o, nd) in zip(ntxt, flat):
        if nd.style.color == BAND:
            t.set_fontweight("normal")
            t.set_style("italic")
            t.set_color("#6b6b6b")
            # bagpype sizes node text from one global font size; shrink (or
            # drop) captions that would spill out of their band
            avail = nd.duration - 0.35
            for fs in (8.0, 7.2, 6.5):
                if len(t.get_text()) * 0.602 * fs / 72.0 / IU <= avail:
                    t.set_fontsize(fs)
                    break
            else:
                t.set_text("")
        else:
            t.set_fontsize(8.5 if nd.duration == 1 else 9.5)
            t.set_zorder(6)
        if nd.label == "COMb":
            t.set_text("COM\nb2-3")
            t.set_fontsize(6.5)
        elif nd.label == "COM" and o is r["G"]:
            t.set_text("COM\nb0-1")
            t.set_fontsize(6.5)

    # ---- instruction labels: left-aligned code column --------------------
    for t in ylab:
        t.set_ha("left")
        t.set_x(X_LBL)
        t.set_fontsize(9.5)
        lab = t.get_text()
        if lab.startswith("  frontend"):
            t.set_color(VIOLET if B else "#7a7a7a")
            t.set_style("italic")
        if "jr a5" in lab:
            t.set_color(RED if B else TEAL)
            t.set_fontweight("bold")
        if lab.startswith("row G") or lab.startswith("row I "):
            t.set_color(GOLD_E)
            t.set_fontweight("bold")
        if lab.startswith("  G.") or lab.startswith("  H."):
            t.set_color(NAVY)

    # ---- x axis: cycles relative to W ------------------------------------
    for t in xlab:
        c = int(round(t.get_position()[0]))
        t.set_text("W" if c == 0 else ("%+d" % c))
        t.set_fontsize(8)
        t.set_color("#1a1a1a" if c == 0 else "#4f4f4f")
        if c == 0:
            t.set_fontweight("bold")
        if B and c == R:
            t.set_color(RED)
            t.set_fontweight("bold")
    ax.text(X_LBL, 0.4, "cycle:", ha="left", va="center", fontsize=8.5,
            color="#3f3f3f", family=SANS)

    # W reference line, in both panels, so the chain lines up across the seam
    ax.plot([0, 0], [0.62, n + 0.45], ls=(0, (1, 3)), lw=1.2, color="#8a8a8a",
            alpha=0.8, zorder=0.5)

    ts1, ts2 = com["G01"], com["I"]
    gap = ts2 - ts1

    # ---- measured interval bracket ---------------------------------------
    for x in (ts1, ts2):
        ax.plot([x, x], [0.62, n + 0.62], ls=(0, (4, 3)), lw=1.4,
                color=GOLD_E, alpha=0.8, zorder=0.5)
    ax.annotate("", xy=(ts1, n + 0.62), xytext=(ts2, n + 0.62),
                arrowprops=dict(arrowstyle="<|-|>", color=GOLD_E, lw=2.0,
                                shrinkA=0, shrinkB=0, mutation_scale=13))
    mid = (ts1 + ts2) / 2
    ax.text(mid, n + 0.98, "T2 - T1  =  (W+14) - (W%+d)" % ts1,
            ha="center", va="center", fontsize=9, color=GOLD_E, family=SANS,
            zorder=7, bbox=dict(fc="white", ec="none", alpha=0.92,
                                boxstyle="round,pad=0.15"))
    big = "measured block latency = %d cycles" % gap
    half = len(big) * 0.60 * 13 / 72.0 / 2 / IU
    ax.text(min(mid, XMAX + 0.5 - half - 0.15), n + 1.45, big,
            ha="center", va="center", fontsize=13, fontweight="bold",
            color=GOLD_E, family=SANS, zorder=7,
            bbox=dict(fc="white", ec=GOLD_E, lw=1.2,
                      boxstyle="round,pad=0.3"))

    # timestamp tags
    for tag, x, key in (("T1", ts1, "G"), ("T2", ts2, "I")):
        ax.text(x, y(r[key]) + 0.52, tag, ha="center", va="center",
                fontsize=9, fontweight="bold", color=GOLD_E, family=SANS,
                zorder=8, bbox=dict(fc="white", ec="none", alpha=0.95,
                                    boxstyle="round,pad=0.12"))

    # ---- shared chain annotations (identical in both panels) -------------
    callout(ax, "W = the cycle fld fa5 returns data", -5.5, y(r["fld"]),
            fontsize=8.5, color=NAVY, ha="right")
    callout(ax,
            "the store's DATA is a SECOND, internal micro-op: it issues,\n"
            "re-reads fa5 and walks the value to the store queue --\n"
            "7 more cycles after the multiply lands",
            7.2, y(r["fsd"]), (8, y(r["fsd"]) + 0.36), RED, ha="right",
            rad=-0.3, axy=(7.4, y(r["fsd"]) + 0.30), fontsize=8.5)

    # ---- per-panel annotations -------------------------------------------
    if B:
        # the redirect fires 5 cycles before the jr commits
        yy = y(r["K'"]) - 0.44
        ax.annotate("", xy=(R, yy), xytext=(com["K'"], yy),
                    arrowprops=dict(arrowstyle="<|-|>", color=RED, lw=1.4,
                                    shrinkA=0, shrinkB=0, mutation_scale=10))
        ax.text((R + com["K'"]) / 2, yy, "redirect 5 cyc before commit",
                ha="center", va="center", fontsize=7.5, color=RED,
                family=SANS, zorder=8,
                bbox=dict(fc="white", ec="none", alpha=0.97,
                          boxstyle="round,pad=0.1"))
        ax.text(R, y(r["K'"]) + 0.52, "MISPREDICT", ha="center", va="center",
                fontsize=8.5, fontweight="bold", color=RED, family=SANS,
                zorder=8, bbox=dict(fc="white", ec=RED, lw=1.0,
                                    boxstyle="round,pad=0.18"))
        callout(ax,
                "jr a5 mispredicts: brinfo -> b2 at R, and the redirect goes out\n"
                "5 cycles BEFORE the jr itself commits at R+5 -- a branch does not\n"
                "wait to reach the commit head.  The squash is PARTIAL: only uops\n"
                "YOUNGER than the jr are killed, so H'-K' keep committing.",
                -12.3, y(r["I'"]) - 0.45, (R + 1.05, y(r["K'"]) + 0.52), RED,
                rad=0.12, axy=(-12.5, y(r["I'"]) - 0.62), fontsize=8.5)
        callout(ax,
                "only the FRONTEND is cleared (F1-F4, fetch buffer, FTQ enq):\n"
                "F0..F4 + decode take 6 cyc to the first dispatch",
                -11.3, y(r["FR"]) + 0.06, (R + 5.4, y(r["FR"]) - 0.02),
                VIOLET, rad=0.2, axy=(-11.6, y(r["FR"]) + 0.06), fontsize=8.5)
        ax.text(-6.0, (y(r["F"]) + y(r["G"])) / 2, "$\\Delta$=2", ha="center",
                va="center", fontsize=8.5, fontweight="bold", color="#4f4f4f",
                family=SANS, zorder=8,
                bbox=dict(fc="white", ec="#b0b0b0", lw=0.8,
                          boxstyle="round,pad=0.14"))
        callout(ax, "taken j 22cc4: a 2-cycle fetch bubble",
                -6.9, y(r["G"]) - 0.02, fontsize=8, color="#4f4f4f",
                ha="right")
        callout(ax,
                "commit is NOT backed up here: everything older retired by R+13\n"
                "and nothing is queued ahead of row G, so its banks 0-1 (fld fa5\n"
                "and j) retire the moment they are ready -- T1 lands at W+3",
                -1.9, y(r["C"]) + 0.34, (ts1 - 0.45, y(r["G"]) - 0.10), NAVY,
                rad=-0.22, axy=(-2.1, y(r["C"]) - 0.05), fontsize=8.5)
        ax.annotate("", xy=(com["D"] + 0.6, y(r["B"])),
                    xytext=(com["E"] - 0.6, y(r["B"])),
                    arrowprops=dict(arrowstyle="<|-|>", color=GREY, lw=1.5,
                                    shrinkA=0, shrinkB=0, mutation_scale=11))
        ax.text((com["D"] + com["E"]) / 2, y(r["A"]) - 0.10,
                "commit idle: 5 cyc\nnothing older left to retire", ha="center",
                va="center", fontsize=8.5, color="#5a5a5a", family=SANS,
                zorder=8, bbox=dict(fc="white", ec="none", alpha=0.95,
                                    boxstyle="round,pad=0.2"))
    else:
        ax.text(R, y(r["K'"]) + 0.52, "PREDICTED OK", ha="center", va="center",
                fontsize=8.5, fontweight="bold", color=TEAL, family=SANS,
                zorder=8, bbox=dict(fc="white", ec=TEAL, lw=1.0,
                                    boxstyle="round,pad=0.18"))
        ax.plot([R, R], [0.62, n + 0.45], ls=(0, (5, 3)), lw=1.5, color=TEAL,
                alpha=0.85, zorder=0.5)
        callout(ax,
                "jr a5 is predicted correctly: no redirect, no refetch.  Fetch and\n"
                "execute run far ahead of commit, so every row of iteration k is\n"
                "already in the ROB and finished -- they only lack a commit slot.",
                R - 2.1, n + 1.45, fontsize=8.5, color=TEAL, ha="left")
        callout(ax,
                "in-order commit is saturated: 11 finished rows retire back to\n"
                "back, one per cycle, and row G is at the back of that queue --\n"
                "T1 is drain-limited and lands at W+9, not W+3",
                5.4, y(r["C"]) + 0.10, (ts1 - 0.45, y(r["G"]) - 0.10), NAVY,
                rad=-0.22, axy=(5.2, y(r["C"]) - 0.30), fontsize=8.5)

        # bracket over the saturated drain
        ax.annotate("", xy=(com["H'"], n + 0.62), xytext=(ts1, n + 0.62),
                    arrowprops=dict(arrowstyle="<|-|>", color=GREY, lw=1.6,
                                    shrinkA=0, shrinkB=0, mutation_scale=11))
        ax.text((com["H'"] + ts1) / 2, n + 0.98,
                "commit saturated: 11 rows retire back to back",
                ha="center", va="center", fontsize=8.5, color="#5a5a5a",
                family=SANS, zorder=7,
                bbox=dict(fc="white", ec="none", alpha=0.92,
                          boxstyle="round,pad=0.15"))

    # ---- panel b: the race, in the top margin ----------------------------
    if B:
        ax.plot([R, R], [0.62, n + 2.95], ls=(0, (5, 3)), lw=1.5, color=RED,
                alpha=0.85, zorder=0.5)
        ax.text(R, n + 2.95, "R = redirect", ha="center", va="bottom",
                fontsize=9, fontweight="bold", color=RED, family=SANS,
                zorder=8)
        ax.annotate("", xy=(R, n + 0.62), xytext=(com["K'"], n + 0.62),
                    arrowprops=dict(arrowstyle="<|-|>", color=GREY, lw=1.6,
                                    shrinkA=0, shrinkB=0, mutation_scale=11))
        ax.text((R + com["K'"]) / 2, n + 0.98,
                "drain: ~5 cyc  (4 ROB rows, ~14 older uops)", ha="center",
                va="center", fontsize=8.5, color="#5a5a5a", family=SANS,
                zorder=7, bbox=dict(fc="white", ec="none", alpha=0.92,
                                    boxstyle="round,pad=0.15"))
        ax.annotate("", xy=(R, n + 1.62), xytext=(com["A"], n + 1.62),
                    arrowprops=dict(arrowstyle="<|-|>", color=VIOLET, lw=1.8,
                                    shrinkA=0, shrinkB=0, mutation_scale=12))
        ax.text((R + com["A"]) / 2, n + 1.98,
                "frontend restart: ~10 cyc to the first correct-path commit",
                ha="center", va="center", fontsize=8.5, color=VIOLET,
                family=SANS, zorder=7,
                bbox=dict(fc="white", ec="none", alpha=0.92,
                          boxstyle="round,pad=0.15"))
        ax.text(-7.6, n + 2.52,
                "restart (~10 cyc)  >  drain (~5 cyc)   =>   commit runs dry",
                ha="left", va="center", fontsize=10.5, fontweight="bold",
                color="#1a1a1a", family=SANS, zorder=8,
                bbox=dict(fc="white", ec="#1a1a1a", lw=1.0,
                          boxstyle="round,pad=0.25"))

    # ---- titles -----------------------------------------------------------
    if not B:
        fig.text(0.004, 1 - 0.17 / fig_h,
                 "B7 (fmul + store, 0x2003c-0x2004c) on BOOM v3: one fixed "
                 "14-cycle chain, measured two ways",
                 ha="left", va="top", fontsize=15, fontweight="bold",
                 family=SANS, color="#1a1a1a")
        sub = ("jr a5 predicted correctly -- fetch runs ahead, commit is the "
               "bottleneck, so T1 = commit(j) is drain-limited at W+9")
    else:
        sub = ("jr a5 mispredicts at R = W-18 -- younger uops squashed, the "
               "frontend restart outlasts the drain, so commit runs dry and "
               "T1 = commit(j) lands at W+3")
    fig.text(0.004, 1 - (0.62 if not B else 0.14) / fig_h,
             panel, ha="left", va="top", fontsize=17, fontweight="bold",
             family=SANS)
    fig.text(0.022, 1 - (0.64 if not B else 0.16) / fig_h, sub,
             ha="left", va="top", fontsize=11.5, family=SANS, color="#2a2a2a")

    # ---- legend (bottom of panel b only) ---------------------------------
    if ax.get_legend():
        ax.get_legend().remove()
    if B:
        handles = [
            Patch(fc=CHAIN, ec="#4a4a4a", label="fixed dependency chain (identical in a and b)"),
            Patch(fc=CHAIN_D, ec="#4a4a4a", label="the 4-cycle double-precision multiply"),
            Patch(fc=UOP, ec="#4a4a4a", label="2nd micro-op: store data -> store queue"),
            Patch(fc=DISP, ec="#4a4a4a", label="dispatch into the ROB"),
            Patch(fc=COMMIT, ec="#4a4a4a", label="ROB row commit (retire)"),
            Patch(fc=TS, ec=GOLD_E, lw=2.0, label="timestamp recorded by the trace hardware"),
            Patch(fc=FRONT, ec=VIOLET, label="frontend refetch: F0-F4 + decode"),
            Patch(fc=MISP, ec=RED, lw=2.0, label="redirect cycle (mispredicting jr)"),
            Patch(fc=PRED, ec=TEAL, lw=2.0, label="the same jr, correctly predicted"),
            Patch(fc=BAND, ec="#c9c9c9", ls="--", label="finished / ready, waiting for a commit slot"),
            Line2D([0], [0], color=NAVY, lw=1.8, label="data dependence"),
            Line2D([0], [0], color=GREY, lw=1.8, label="in-order dispatch / commit order"),
        ]
        fig.legend(handles=handles, loc="lower left", ncol=4, frameon=False,
                   handlelength=1.6, columnspacing=1.8, labelspacing=0.55,
                   borderaxespad=0.0,
                   bbox_to_anchor=(LEFT_IN / FIG_W - 0.035, 0.012),
                   prop=dict(family=SANS, size=9))

    out = os.path.join(OUTDIR, "fig.b7_pipeline_%s.png" % panel)
    fig.savefig(out, dpi=150, facecolor="white")
    fig.savefig(out[:-3] + "pdf", facecolor="white")   # vector companion
    plt.close(fig)
    return out


def main():
    os.makedirs(OUTDIR, exist_ok=True)
    pa = render("a")
    pb = render("b")

    from PIL import Image
    ia, ib = Image.open(pa), Image.open(pb)
    w = max(ia.width, ib.width)
    combo = Image.new("RGB", (w, ia.height + ib.height), "white")
    combo.paste(ia, (0, 0))
    combo.paste(ib, (0, ia.height))
    out = os.path.join(OUTDIR, "fig.b7_pipeline.png")
    combo.save(out)
    print(pa)
    print(pb)
    print(out, combo.size)


if __name__ == "__main__":
    main()
