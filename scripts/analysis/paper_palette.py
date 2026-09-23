"""One visual language for the paper's figures: NPG palette, sizing, export.

Imported by every plot_*.py that targets the manuscript, so a change here moves
all of them together rather than letting each figure drift into its own look.

Palette is NPG (Nature Publishing Group, via ggsci), used by role rather than by
index -- navy carries the main series, coral the one result the eye should land
on, and warm tan is the neutral for context and "everything else".
"""
import matplotlib as mpl
import numpy as np

MM = 1 / 25.4
SINGLE_COL = 89.0     # mm
DOUBLE_COL = 183.0    # mm
MAX_HEIGHT = 170.0    # mm, leaves room for the caption

# --------------------------------------------------------------------------- venues
# Figure text is anchored to the venue's CAPTION size, because that is the text it
# sits next to on the page. Nature's body is ~7 pt so 6 pt labels look right there;
# an ACM/IEEE paper has 9-10 pt body and 8 pt captions, and the same 6 pt reads as
# tiny. Column widths are the real \columnwidth / \textwidth of the class.
#
# THE INVARIANT: build at final size and insert with \includegraphics{fig.pdf} and
# NO width= argument. `width=\columnwidth` on a figure that is already the column
# width silently rescales every font, which is what every ad-hoc font fix has
# really been chasing.
VENUES = {
    # acmart sigconf: body 9 pt, caption 8 pt, \columnwidth 241.15 pt, \textwidth 505.89 pt
    'acm':    dict(base=8.0, tick=7.0, panel=9.0, single=84.8, double=177.8,
                   axes_lw=0.7, tick_lw=0.5, grid_lw=0.4),
    # IEEEtran conference: body 10 pt, caption 8 pt, \columnwidth 252 pt
    'ieee':   dict(base=8.0, tick=7.0, panel=9.0, single=88.6, double=181.9,
                   axes_lw=0.7, tick_lw=0.5, grid_lw=0.4),
    # the Nature baseline the other figures in this repo currently use
    'nature': dict(base=6.0, tick=5.0, panel=8.0, single=89.0, double=183.0,
                   axes_lw=0.6, tick_lw=0.5, grid_lw=0.3),
}
MIN_PT = 7.0          # never put text smaller than this on a conference page

NAVY, CORAL, CYAN, TEAL = '#3C5488', '#E64B35', '#4DBBD5', '#00A087'
MINT, BROWN, SALMON, SLATE = '#91D1C2', '#7E6148', '#F39B7F', '#8491B4'
NPG = [NAVY, CORAL, CYAN, TEAL, MINT, BROWN, SALMON, SLATE]

NEUTRAL = '#DFD7CE'      # warm tan tint: context, reference, pooled remainder
NEUTRAL_PT = '#C2C8DA'   # slate tint: context scatter points
INK, INK2 = '#333333', '#666666'
GRID = '#E4E4E4'

# Past three hues colour stops carrying the argument and starts being decoration,
# so anything beyond this pools into NEUTRAL instead of taking a fifth hue.
#
# Slot 4 is MINT, not the TEAL that NPG's categorical order puts there: coral and
# teal sit at relative luminance 0.221 and 0.269, so they collapse to the same
# grey in print (verified by rendering, not by eye). With mint the five slots run
# 0.091 / 0.221 / 0.419 / 0.555 / 0.687, every neighbour >=0.13 apart. Mint's
# weakest deuteranope pair is against cyan, which it still separates from by 0.136
# in lightness -- so identity survives whichever channel a reader is missing.
CATEGORICAL = [NAVY, CORAL, CYAN, MINT]
# Dash patterns duplicate the categorical identity for line/step plots, where
# grayscale and colour-deficient readers cannot lean on hue.
CATEGORICAL_DASH = [(0, ()), (0, (3.5, 1.2)), (0, (1.4, 1.2)), (0, (5, 1.2, 1, 1.2))]


def tint(hex_, t):
    """Mix a colour toward white. t=0 unchanged, t=1 white.

    Tinting, not alpha: alpha over gridlines and overlapping marks changes the
    colour that actually lands on the page.
    """
    r, g, b = (int(hex_[i:i + 2], 16) for i in (1, 3, 5))
    return '#%02X%02X%02X' % tuple(round(c + (255 - c) * t) for c in (r, g, b))


def luminance(hex_):
    """Relative luminance (WCAG), i.e. what survives a grayscale print."""
    c = np.array([int(hex_[i:i + 2], 16) / 255 for i in (1, 3, 5)])
    c = np.where(c <= 0.04045, c / 12.92, ((c + 0.055) / 1.055) ** 2.4)
    return float(c @ [0.2126, 0.7152, 0.0722])


def ordered(n, base=NAVY, top=NEUTRAL):
    """n tints of one hue at equal luminance steps, dark to light.

    For ranks, doses, ablation steps -- anything ordered, which must never be
    encoded with different hues. The steps stop short of `top`'s luminance so an
    ordered ramp and the neutral tier above it stay distinguishable in grayscale.
    """
    if n < 1:
        return []
    if n == 1:
        return [base]
    lo, hi = luminance(base), luminance(top)
    targets = np.linspace(lo, hi, n + 1)[:n]
    ts = np.linspace(0, 1, 2001)
    lut = np.array([luminance(tint(base, t)) for t in ts])
    return [tint(base, ts[np.argmin(np.abs(lut - L))]) for L in targets]


def style(venue='nature', scale=1.0, **over):
    """rcParams for a venue. `venue='acm'` sizes text to an 8 pt caption.

    Defaults to 'nature' so existing figures are unchanged; pass venue='acm' to
    adopt the conference standard. `scale` multiplies every text size for the rare
    case where a figure is genuinely inserted at other than 1:1.
    """
    v = VENUES[venue]
    base, tick, panel = (v['base'] * scale, v['tick'] * scale, v['panel'] * scale)
    if min(base, tick) < MIN_PT and venue != 'nature':
        print(f'  note: {min(base, tick):.1f} pt text is below the {MIN_PT:.0f} pt '
              f'conference floor', flush=True)
    mpl.rcParams.update({
        'font.family': 'sans-serif',
        'font.sans-serif': ['Arial', 'Helvetica', 'Liberation Sans',
                            'Nimbus Sans', 'DejaVu Sans'],
        'font.size': base,
        'axes.labelsize': base, 'axes.titlesize': base,
        'xtick.labelsize': tick, 'ytick.labelsize': tick,
        'legend.fontsize': base,
        'axes.linewidth': v['axes_lw'],
        'xtick.major.width': v['tick_lw'], 'ytick.major.width': v['tick_lw'],
        'xtick.major.size': 2.0, 'ytick.major.size': 2.0,
        'lines.linewidth': 1.0, 'lines.markersize': 3.5,
        'axes.prop_cycle': mpl.cycler(color=NPG),
        'legend.frameon': False,
        'pdf.fonttype': 42, 'ps.fonttype': 42,
        'savefig.dpi': 300,
        **over,
    })
    return dict(base=base, tick=tick, panel=panel,
                single=v['single'], double=v['double'], grid_lw=v['grid_lw'])


def fit_tight(fig, w_mm, h_mm, pad_in=0.02, tol_mm=0.15, iters=10):
    """Size the canvas so the *cropped* figure is exactly w_mm x h_mm.

    bbox_inches='tight' crops to drawn content, so a figure asked for at 89 mm
    lands smaller and is scaled back up when placed at column width, silently
    inflating every font past the spec. Content extent is monotone in canvas
    extent, so iterating on the difference converges in a few passes.
    """
    tw, th = w_mm * MM - 2 * pad_in, h_mm * MM - 2 * pad_in
    for _ in range(iters):
        fig.canvas.draw()
        bb = fig.get_tightbbox(fig.canvas.get_renderer())
        dw, dh = tw - bb.width, th - bb.height
        if abs(dw) < tol_mm * MM and abs(dh) < tol_mm * MM:
            break
        w, h = fig.get_size_inches()
        fig.set_size_inches(w + dw, h + dh)
    return bb.width / MM + 2 * pad_in / MM, bb.height / MM + 2 * pad_in / MM


def save(fig, out, pad_in=0.02):
    fig.savefig(f'{out}.pdf', bbox_inches='tight', pad_inches=pad_in)
    fig.savefig(f'{out}.png', dpi=300, bbox_inches='tight', pad_inches=pad_in)
