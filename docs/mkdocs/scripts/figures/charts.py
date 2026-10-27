"""Draws the measurement charts as inline SVGs into docs/images/.

Generated files:

- compile_times.svg: percent change in compile time per option at -O0 (integration/compile_times.md)
- compile_times_pch.svg, compile_times_modules.svg: percent change per translation unit with a precompiled header or
  `import nlohmann.json;` at -O0, plus the one-off build cost (integration/compile_times.md)
- binary_sizes_<file>.svg: encoded size per binary format relative to minified JSON, one panel per test file
  (features/binary_formats/index.md, reused on features/performance.md)
- ordered_json_scaling.svg: parse time of a flat object for json vs. ordered_json (features/performance.md)

Every number below is copied from the tables on those pages (or, where noted, computed from the milliseconds they
report); the tables stay on the pages as the accessible fallback. Update both together. The SVGs are not images:
the pages include their text with `--8<-- "images/<name>.svg"`, so they pick up the colours and fonts of the page
(see the `nj-charts` rules in docs/css/fig-charts.css). Run `python3 scripts/figures/charts.py` from docs/mkdocs after
changing data or drawing, and commit the generated files. In SVG text write the word JSON as `J&#8203;SON`,
otherwise the abbreviation extension wraps it in an <abbr> and the text disappears.
"""
import html
import math
import re
from pathlib import Path

OUT = Path(__file__).resolve().parents[2] / "docs" / "images"
MINUS = "&#8722;"
JSON = "J&#8203;SON"


# words the abbreviation extension (includes/glossary.md) would wrap in <abbr> inside the SVG text
ABBR = re.compile(r"(?<![\w;])(BJData|BON8|BSON|CBOR|GCC|UBJSON|MsgPack|JSON|DOM|SAX)(?!\w)")


def protect(text):
    return ABBR.sub(lambda m: m.group(1)[0] + "&#8203;" + m.group(1)[1:], text)


def esc(s):
    return html.escape(s, quote=True).replace("J&amp;#8203;SON", JSON).replace("&amp;#8722;", MINUS)


def write(name, W, H, cls, tid, title, desc, body):
    s = ['<svg class="nj-fig nj-charts %s" viewBox="0 0 %g %g" role="img" aria-labelledby="%s %s-d" '
         'xmlns="http://www.w3.org/2000/svg">' % (cls, W, H, tid, tid),
         '<title id="%s">%s</title>' % (tid, esc(title)),
         '<desc id="%s-d">%s</desc>' % (tid, esc(desc))]
    s += body
    s.append('</svg>')
    (OUT / name).write_text(protect("\n".join(s)) + "\n")


def hbar(x0, x1, y, h, r=4):
    """Horizontal bar from the baseline x0 to x1, rounded only at the data end."""
    if abs(x1 - x0) < 0.5:
        return "M%g %g h0.5 v%g h-0.5 Z" % (x0, y, h)
    r = min(r, h / 2, abs(x1 - x0))
    s = 1 if x1 > x0 else -1
    return ("M%g %g H%g Q%g %g %g %g V%g Q%g %g %g %g H%g Z"
            % (x0, y, x1 - s * r, x1, y, x1, y + r, y + h - r, x1, y + h, x1 - s * r, y + h, x0))


def pct(v):
    if v == 0:
        return "0 %"
    return ("+" if v > 0 else MINUS) + "%g %%" % abs(v)


# ---------- compile times (integration/compile_times.md, -O0 columns) ----------
# (label, translation unit, Apple clang %, GCC 16 %, computed?), ordered by saving
COMPILE = [
    ("json_fwd.hpp instead of json.hpp", "header-only TU", -62, -82, False),
    ("extern template", "parsing TU", -7, -21, False),
    ("JSON_NO_AUTOMATIC_UDLS", "model TU", -11, -11, False),
    ("JSON_NO_AUTOMATIC_UDLS", "parsing TU", -1, -2, False),
    ("JSON_HAS_FILESYSTEM=0 + JSON_NO_IO", "model TU", -8, -11, False),
    ("JSON_HAS_FILESYSTEM=0", "model TU", -5, -9, False),
    # computed from the ms in "Options without effect on compile times": 1034/1051, 1756/1801, 1055/1051, 1783/1801
    ("JSON_NO_IO", "model TU", round((1034 / 1051 - 1) * 100), round((1756 / 1801 - 1) * 100), True),
    ("JSON_USE_GLOBAL_UDLS=0", "model TU", round((1055 / 1051 - 1) * 100), round((1783 / 1801 - 1) * 100), True),
]


def compile_times():
    W, L, R = 470, 8, 402
    lo, hi = -90, 10
    X = lambda v: L + (v - lo) / (hi - lo) * (R - L)
    top, pitch, bh = 64, 52, 12
    H = top + pitch * len(COMPILE) + 30
    b = []
    # legend
    b.append('<rect class="nj-charts-clang" x="%g" y="10" width="12" height="12" rx="3"/>' % L)
    b.append('<text class="nj-charts-leg" x="%g" y="20.5">Apple clang</text>' % (L + 18))
    b.append('<rect class="nj-charts-gcc" x="%g" y="10" width="12" height="12" rx="3"/>' % (L + 118))
    b.append('<text class="nj-charts-leg" x="%g" y="20.5">GCC 16</text>' % (L + 136))
    # grid and ticks
    axis_y = top + pitch * len(COMPILE) - 8
    for t in (-80, -60, -40, -20):
        b.append('<line class="nj-charts-grid" x1="%g" y1="%g" x2="%g" y2="%g"/>' % (X(t), top - 6, X(t), axis_y))
        b.append('<text class="nj-charts-tick" x="%g" y="%g">%s</text>' % (X(t), axis_y + 16, pct(t)))
    b.append('<text class="nj-charts-tick" x="%g" y="%g">0 %%</text>' % (X(0), axis_y + 16))
    b.append('<text class="nj-charts-tick nj-charts-tick--l" x="%g" y="%g">&#8592; faster</text>' % (L, axis_y + 34))
    b.append('<text class="nj-charts-tick nj-charts-tick--r" x="%g" y="%g">slower &#8594;</text>' % (W - 8, axis_y + 34))
    for i, (label, tu, clang, gcc, computed) in enumerate(COMPILE):
        y = top + i * pitch
        b.append('<text class="nj-charts-rowlabel" x="%g" y="%g"><tspan class="nj-charts-code">%s</tspan>'
                 '<tspan class="nj-charts-sub"> &#183; %s%s</tspan></text>'
                 % (L, y - 2, esc(label), tu, "*" if computed else ""))
        for j, (v, cls, name) in enumerate(((clang, "clang", "Apple clang"), (gcc, "gcc", "GCC 16"))):
            by = y + 6 + j * (bh + 2)
            b.append('<path class="nj-charts-%s" d="%s"><title>%s, %s (%s): %s</title></path>'
                     % (cls, hbar(X(0), X(v), by, bh), esc(label), tu, name, esc(pct(v))))
            b.append('<text class="nj-charts-val" x="%g" y="%g">%s</text>' % (max(X(0), X(v)) + 5, by + bh - 1.5, pct(v)))
    b.append('<line class="nj-charts-zero" x1="%g" y1="%g" x2="%g" y2="%g"/>' % (X(0), top - 6, X(0), axis_y))
    H = axis_y + 44
    desc = "; ".join("%s on a %s: Apple clang %s, GCC 16 %s" % (label, tu.replace("TU", "translation unit"),
                     pct(c).replace(MINUS, "-"), pct(g).replace(MINUS, "-")) for label, tu, c, g, _ in COMPILE)
    write("compile_times.svg", W, H, "nj-charts--compile", "nj-charts-ct",
          "Change in compile time against the default configuration at -O0, Apple clang and GCC 16",
          "Grouped horizontal bars, negative is faster. " + desc + ".", b)


# ---------- precompiled headers and C++20 modules (integration/compile_times.md, -O0 columns) ----------
# Per-TU medians of the wall-clock time in ms from the tables "Use precompiled headers" (-std=c++17) and
# "Use C++20 modules" (-std=c++20): {translation unit: {compiler: (default ms, with PCH/module ms)}}, plus the one-off
# build cost in ms per compiler. None instead of a value means "not measured"; NOT_AVAILABLE then gives the reason.
PCH = {
    "model TU": {"Apple clang": (1045, 594), "GCC 16": (1789, 1060)},
    "parsing TU": {"Apple clang": (1148, 714), "GCC 16": (2498, 1884)},
}
PCH_BUILD = {"Apple clang": 771, "GCC 16": 2254}
MODULES = {
    "model TU": {"Apple clang": (1311, 680), "GCC 16": (2156, 1153)},
    "parsing TU": {"Apple clang": (1387, 800), "GCC 16": (2838, 1810)},
}
MODULES_BUILD = {"Apple clang": 1630, "GCC 16": 2538}
NOT_AVAILABLE = {}   # compiler: reason


def tradeoff(name, tid, rows, build, what, title, desc_intro):
    """Percent change per TU (bars) and the one-off build cost (text rows below) for two compilers."""
    W, L, R = 440, 8, 372
    lo, hi = -60, 0
    X = lambda v: L + (v - lo) / (hi - lo) * (R - L)
    top, pitch, bh = 64, 52, 12
    comps = (("Apple clang", "clang"), ("GCC 16", "gcc"))
    b, desc = [], []
    b.append('<rect class="nj-charts-clang" x="%g" y="10" width="12" height="12" rx="3"/>' % L)
    b.append('<text class="nj-charts-leg" x="%g" y="20.5">Apple clang</text>' % (L + 18))
    b.append('<rect class="nj-charts-gcc" x="%g" y="10" width="12" height="12" rx="3"/>' % (L + 118))
    b.append('<text class="nj-charts-leg" x="%g" y="20.5">GCC 16</text>' % (L + 136))
    axis_y = top + pitch * len(rows) - 8
    for t in (-50, -25):
        b.append('<line class="nj-charts-grid" x1="%g" y1="%g" x2="%g" y2="%g"/>' % (X(t), top - 6, X(t), axis_y))
        b.append('<text class="nj-charts-tick" x="%g" y="%g">%s</text>' % (X(t), axis_y + 16, pct(t)))
    b.append('<text class="nj-charts-tick" x="%g" y="%g">0 %%</text>' % (X(0), axis_y + 16))
    b.append('<text class="nj-charts-tick nj-charts-tick--l" x="%g" y="%g">&#8592; faster per TU</text>' % (L, axis_y + 34))
    for i, (tu, vals) in enumerate(rows.items()):
        y = top + i * pitch
        b.append('<text class="nj-charts-rowlabel" x="%g" y="%g">%s<tspan class="nj-charts-sub"> &#183; %s</tspan></text>'
                 % (L, y - 2, tu, esc(what)))
        for j, (comp, cls) in enumerate(comps):
            by = y + 6 + j * (bh + 2)
            pair = vals[comp]
            if pair is None:
                b.append('<text class="nj-charts-note" x="%g" y="%g">%s: not available: %s</text>'
                         % (L, by + bh - 1.5, comp, esc(NOT_AVAILABLE.get(comp, "not measured"))))
                desc.append("%s, %s: not available" % (tu, comp))
                continue
            d, w = pair
            v = round((w / d - 1) * 100)
            b.append('<path class="nj-charts-%s" d="%s"><title>%s, %s: %d ms by default, %d ms %s (%s)</title></path>'
                     % (cls, hbar(X(0), X(v), by, bh), tu, comp, d, w, esc(what), esc(pct(v))))
            b.append('<text class="nj-charts-val" x="%g" y="%g">%s</text>' % (X(0) + 5, by + bh - 1.5, pct(v)))
            desc.append("%s, %s: %s (%d ms to %d ms)" % (tu, comp, pct(v).replace(MINUS, "-"), d, w))
    b.append('<line class="nj-charts-zero" x1="%g" y1="%g" x2="%g" y2="%g"/>' % (X(0), top - 6, X(0), axis_y))
    # one-off cost
    y = axis_y + 62
    b.append('<text class="nj-charts-rowlabel" x="%g" y="%g">One-off cost<tspan class="nj-charts-sub"> &#183; built once, '
             'reused by every TU</tspan></text>' % (L, y))
    for j, (comp, cls) in enumerate(comps):
        yy = y + 20 + j * 20
        b.append('<rect class="nj-charts-%s" x="%g" y="%g" width="10" height="10" rx="2.5"/>' % (cls, L, yy - 9.5))
        ms = build[comp]
        saved = sorted(vals[comp][0] - vals[comp][1] for vals in rows.values() if vals[comp] is not None)
        txt = ("%s: %d ms once, saves %d to %d ms per TU" % (comp, ms, saved[0], saved[-1])) if ms is not None else ("%s: not available: %s" % (comp, NOT_AVAILABLE.get(comp, "not measured")))
        b.append('<text class="nj-charts-val" x="%g" y="%g">%s</text>' % (L + 16, yy, esc(txt)))
        desc.append("one-off build, %s: %s" % (comp, ("%d ms" % ms) if ms is not None else "not available"))
    H = y + 20 + 20 * len(comps)
    write(name, W, H, "nj-charts--compile", tid, title, desc_intro + " " + "; ".join(desc) + ".", b)


# ---------- binary sizes (features/binary_formats/index.md, "Sizes") ----------
FORMATS = ["BJData", "BON8", "BSON", "CBOR", "MessagePack", "UBJSON"]   # colour slots 1-6, same in every panel
SIZES = {
    "canada.json":       [53.2, 50.5, 85.8, 50.5, 50.5, 53.2],
    "twitter.json":      [91.1, 83.8, 95.2, 86.3, 86.0, 91.3],
    "citm_catalog.json": [78.1, 63.5, 95.8, 68.4, 68.5, 78.2],
    "jeopardy.json":     [96.6, 87.5, 106.7, 88.0, 87.9, 96.6],
}


def binary_sizes():
    W, L, R = 340, 104, 286
    X = lambda v: L + v / 110 * (R - L)
    top, pitch, bh = 46, 26, 16
    for fname, vals in SIZES.items():
        b, vl = [], []   # value labels go on top of the 100 % line
        lo = min(vals)
        b.append('<text class="nj-charts-panel" x="8" y="18">%s</text>' % fname)
        bottom = top + pitch * len(FORMATS) - 6
        for t in (0, 50):
            b.append('<line class="nj-charts-grid" x1="%g" y1="%g" x2="%g" y2="%g"/>' % (X(t), top - 6, X(t), bottom))
            b.append('<text class="nj-charts-tick" x="%g" y="%g">%d %%</text>' % (X(t), bottom + 15, t))
        for i, (fmt, v) in enumerate(zip(FORMATS, vals)):
            y = top + i * pitch
            best = v == lo
            b.append('<text class="nj-charts-rowlabel nj-charts-fmt%s" x="%g" y="%g">%s</text>'
                     % (" nj-charts-best" if best else "", L - 8, y + bh - 3.5, fmt))
            b.append('<path class="nj-charts-c%d%s" d="%s"><title>%s, %s: %g %% of minified %s%s</title></path>'
                     % (i + 1, "" if best else " nj-charts-dim", hbar(X(0), X(v), y, bh), fname, fmt, v, JSON,
                        " (smallest)" if best else ""))
            vl.append('<text class="nj-charts-val%s" x="%g" y="%g">%.1f %%</text>'
                     % (" nj-charts-best" if best else "", X(v) + 5, y + bh - 3.5, v))
        b.append('<line class="nj-charts-ref" x1="%g" y1="%g" x2="%g" y2="%g"/>' % (X(100), top - 10, X(100), bottom))
        b.append('<text class="nj-charts-tick nj-charts-tick--r" x="%g" y="%g">minified %s = 100 %%</text>'
                 % (X(100) + 2, top - 14, JSON))
        b.append('<text class="nj-charts-tick" x="%g" y="%g">100 %%</text>' % (X(100), bottom + 15))
        b += vl
        H = bottom + 24
        best = [f for f, v in zip(FORMATS, vals) if v == lo]
        desc = "; ".join("%s %g %%" % (f, v) for f, v in zip(FORMATS, vals))
        stem = fname.split(".")[0]
        write("binary_sizes_%s.svg" % stem, W, H, "nj-charts--sizes", "nj-charts-bs-" + stem,
              "Size of %s in each binary format relative to minified %s" % (fname, JSON),
              "%s. Smallest: %s." % (desc, " and ".join(best)), b)


# ---------- json vs. ordered_json (api/ordered_map.md, cited on features/performance.md) ----------
SCALING = [(2000, 0.7, 3.6, 5), (4000, 0.8, 14.0, 19), (8000, 1.6, 67.8, 43), (16000, 3.3, 181.6, 54)]


def scaling():
    W, L, R, T, B = 440, 66, 330, 16, 210
    xs = [n for n, *_ in SCALING]
    X = lambda n: L + math.log2(n / xs[0]) / math.log2(xs[-1] / xs[0]) * (R - L)
    Y = lambda ms: B - (math.log10(ms) - math.log10(0.3)) / (math.log10(300) - math.log10(0.3)) * (B - T)
    b = []
    for t in (1, 10, 100):
        b.append('<line class="nj-charts-grid" x1="%g" y1="%g" x2="%g" y2="%g"/>' % (L, Y(t), R, Y(t)))
        b.append('<text class="nj-charts-tick nj-charts-tick--r" x="%g" y="%g">%g ms</text>' % (L - 6, Y(t) + 4, t))
    b.append('<line class="nj-charts-axis" x1="%g" y1="%g" x2="%g" y2="%g"/>' % (L, B, R, B))
    for n, a, o, f in SCALING:
        b.append('<text class="nj-charts-tick" x="%g" y="%g">%s</text>' % (X(n), B + 16, "{:,}".format(n).replace(",", "&#8201;")))
    for key, idx, cls, name in (("json", 1, "json", "json"), ("ojson", 2, "ojson", "ordered_json")):
        pts = [(X(r[0]), Y(r[idx])) for r in SCALING]
        b.append('<polyline class="nj-charts-%s" points="%s"/>' % (cls, " ".join("%g,%g" % p for p in pts)))
        for (x, y), r in zip(pts, SCALING):
            b.append('<circle class="nj-charts-%s-dot" cx="%g" cy="%g" r="4.5"><title>%s, %d keys: %g ms</title></circle>'
                     % (cls, x, y, name, r[0], r[idx]))
        last = SCALING[-1]
        b.append('<text class="nj-charts-val nj-charts-name-%s" x="%g" y="%g">%s</text>' % (cls, pts[-1][0] + 10, pts[-1][1] - 2, name))
        b.append('<text class="nj-charts-val" x="%g" y="%g">%g ms</text>' % (pts[-1][0] + 10, pts[-1][1] + 13, last[idx]))
        first = SCALING[0]
        dy = 16 if key == "json" else 20
        b.append('<text class="nj-charts-val" x="%g" y="%g">%g ms</text>' % (pts[0][0] + 6, pts[0][1] + dy, first[idx]))
    write("ordered_json_scaling.svg", W, B + 28, "nj-charts--scaling", "nj-charts-sc",
          "Time to parse a flat object of n keys, json against ordered_json, logarithmic axes",
          "2000 keys: json 0.7 ms, ordered_json 3.6 ms (5x). 4000 keys: 0.8 ms and 14.0 ms (19x). "
          "8000 keys: 1.6 ms and 67.8 ms (43x). 16000 keys: 3.3 ms and 181.6 ms (54x).", b)


if __name__ == "__main__":
    compile_times()
    tradeoff("compile_times_pch.svg", "nj-charts-pch", PCH, PCH_BUILD, "with PCH",
             "Compile time per translation unit with a precompiled json.hpp at -O0, and the one-off cost of the PCH",
             "Horizontal bars, negative is faster, medians of nine runs, -std=c++17.")
    tradeoff("compile_times_modules.svg", "nj-charts-mod", MODULES, MODULES_BUILD, "import nlohmann.json",
             "Compile time per translation unit with import nlohmann.json at -O0, and the one-off cost of the module",
             "Horizontal bars, negative is faster, medians of nine runs, -std=c++20 for both.")
    binary_sizes()
    scaling()
