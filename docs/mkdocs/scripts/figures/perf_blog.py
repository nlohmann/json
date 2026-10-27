"""Draws the figures of home/blog/how_3_13_0_got_faster.md as inline SVGs into docs/images/.

Generated files:

- perf_blog_overview.svg: speedup of 3.13.0 over 3.12.0 per workload (Google Benchmark suite)
- perf_blog_timeline_<workload>.svg: speedup over 3.12.0 of eight workloads at every develop commit that changed
  json.hpp or json_view.hpp since 3.12.0, one panel each
- perf_blog_swar.svg: the eight-byte string test on one word of input
- perf_blog_cliffs.svg: operations that were quadratic or worse, 3.12.0 against 3.13.0 (log scale)
- perf_blog_view.svg: parse throughput of json_document, yyjson, simdjson's DOM, Boost.JSON and json::parse

The numbers are copied from the tables of the post (the timeline from data/perf_timeline.csv, which
`tests/benchmarks/history/history.py summarize` writes); the tables stay on the page as the accessible fallback. Update both together.
Like the figures of charts.py, the SVGs are not images: the page includes their text with
`--8<-- "images/<name>.svg"`, so they follow the colours and fonts of the page (`nj-charts` rules in
docs/css/fig-charts.css, `nj-fig` rules in docs/css/brand.css). Run `python3 scripts/figures/perf_blog.py` from
docs/mkdocs after changing data or drawing, and commit the generated files.
"""
import csv
import html
import math
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE.parents[1] / "docs" / "images"
MINUS = "&#8722;"
TIMES = "&#215;"

# words the abbreviation extension (includes/glossary.md) would wrap in <abbr> inside the SVG text
ABBR = re.compile(r"(?<![\w;])(BJData|BON8|BSON|CBOR|GCC|UBJSON|MsgPack|JSON|DOM|SAX|SIMD|UTF|ASCII)(?!\w)")


def protect(text):
    return ABBR.sub(lambda m: m.group(1)[0] + "&#8203;" + m.group(1)[1:], text)


def esc(s):
    return html.escape(s, quote=True).replace("&amp;#", "&#")


def write(name, W, H, cls, tid, title, desc, body):
    s = ['<svg class="nj-fig nj-charts %s" viewBox="0 0 %g %g" role="img" aria-labelledby="%s %s-d" '
         'xmlns="http://www.w3.org/2000/svg">' % (cls, W, H, tid, tid),
         '<title id="%s">%s</title>' % (tid, esc(title)),
         '<desc id="%s-d">%s</desc>' % (tid, esc(desc))]
    s += body
    s.append('</svg>')
    text = protect("\n".join(s)) + "\n"
    assert "\n\n" not in text  # a blank line would end the raw HTML block
    (OUT / name).write_text(text)


def hbar(x0, x1, y, h, r=4):
    """Horizontal bar from the baseline x0 to x1, rounded only at the data end."""
    if abs(x1 - x0) < 0.5:
        return "M%g %g h0.5 v%g h-0.5 Z" % (x0, y, h)
    r = min(r, h / 2, abs(x1 - x0))
    s = 1 if x1 > x0 else -1
    return ("M%g %g H%g Q%g %g %g %g V%g Q%g %g %g %g H%g Z"
            % (x0, y, x1 - s * r, x1, y, x1, y + r, y + h - r, x1, y + h, x1 - s * r, y + h, x0))


def fx(v):
    """speedup factor for labels: 2 significant digits below 10, integers above"""
    if v >= 100:
        return "%d%s" % (round(v), TIMES)
    if v >= 10:
        return "%.0f%s" % (v, TIMES)
    return "%.1f%s" % (v, TIMES) if v >= 1.995 else "%.2f%s" % (v, TIMES)


# ---------- SWAR: one word of a string ----------
def swar():
    text = 'witter",'
    W, H = 640, 312
    L, cw, top = 40, 70, 34
    b = []
    b.append('<text class="fg-h" x="%g" y="20">eight input bytes, loaded as one 64-bit word (byte 0 is the lowest)</text>' % L)
    for i, ch in enumerate(text):
        x = L + i * cw
        special = ch == '"'
        b.append('<rect class="fg-cell" x="%g" y="%g" width="%g" height="40" rx="4"/>' % (x, top, cw - 6))
        if special:
            b.append('<rect class="nj-charts-c2" fill-opacity=".25" x="%g" y="%g" width="%g" height="40" rx="4"/>' % (x, top, cw - 6))
        b.append('<text class="fg-code" x="%g" y="%g" text-anchor="middle">%s</text>' % (x + (cw - 6) / 2, top + 26, esc(ch)))
        b.append('<text class="nj-charts-tick" x="%g" y="%g">0x%02X</text>' % (x + (cw - 6) / 2, top + 58, ord(ch)))
        b.append('<text class="nj-charts-tick" x="%g" y="%g">byte %d</text>' % (x + (cw - 6) / 2, top + 74, i))
    # result row
    y2 = top + 112
    b.append('<text class="fg-h" x="%g" y="%g">swar_string_special(): the high bit of each byte that needs handling</text>' % (L, y2 - 14))
    for i, ch in enumerate(text):
        x = L + i * cw
        special = ch == '"'
        b.append('<rect class="fg-cell" x="%g" y="%g" width="%g" height="34" rx="4"/>' % (x, y2, cw - 6))
        if special:
            b.append('<rect class="nj-charts-c2" fill-opacity=".25" x="%g" y="%g" width="%g" height="34" rx="4"/>' % (x, y2, cw - 6))
        b.append('<text class="fg-code" x="%g" y="%g" text-anchor="middle">%s</text>'
                 % (x + (cw - 6) / 2, y2 + 23, "0x80" if special else "0x00"))
    # conclusion
    y3 = y2 + 70
    b.append('<text class="fg-code" x="%g" y="%g">count_trailing_zeros(0x0080000000000000) = 55</text>' % (L, y3))
    b.append('<text class="fg-code" x="%g" y="%g">55 / 8 = 6: copy bytes 0 to 5 in one go, then handle the quote</text>' % (L, y3 + 26))
    b.append('<text class="fg-note fg-note--l" x="%g" y="%g">No branch per byte: a few subtractions, ANDs and ORs per word,</text>' % (L, y3 + 56))
    b.append('<text class="fg-note fg-note--l" x="%g" y="%g">then one count of trailing zeros.</text>' % (L, y3 + 74))
    write("perf_blog_swar.svg", W, H, "nj-charts--swar", "nj-blog-swar",
          "Finding the end of a run of ordinary string characters eight bytes at a time",
          "The eight bytes w, i, t, t, e, r, quote and comma are loaded as one word. The test sets the high bit only in "
          "byte 6, the quote. Counting trailing zero bits gives 55, divided by eight gives 6: bytes 0 to 5 are copied "
          "at once, then the quote ends the string.", b)


# ---------- overview: speedup per workload (Google Benchmark rows, 3.12.0 time / 3.13.0 time) ----------
# (group, label, speedup), copied from the table "The short version"
OVERVIEW = [
    ("Parsing", "twitter.json", 3.02),
    ("Parsing", "citm_catalog.json", 4.13),
    ("Parsing", "canada.json", 3.46),
    ("Parsing", "canada.json, indented", 6.74),
    ("Parsing", "citm, ordered_json", 6.58),
    ("Parsing", "twitter, std::ifstream", 2.46),
    ("Parsing", "citm, FILE*", 4.76),
    ("Parsing", "citm, accept()", 6.99),
    ("Writing", "dump() twitter", 6.67),
    ("Writing", "dump() canada", 2.95),
    ("Writing", "dump(4) citm", 4.63),
    ("Writing", "to_cbor() twitter", 4.50),
    ("Reading CBOR", "twitter, memory", 3.11),
    ("Reading CBOR", "twitter, FILE*", 6.31),
    ("Values", "diff() canada", 10.44),
    ("Values", "iterate canada", 2.69),
    ("Values", "copy + destroy citm", 1.11),
    ("Values", "== citm", 1.04),
]


def overview():
    W, L, R = 560, 190, 520
    hi = max(v for _, _, v in OVERVIEW)
    hi = math.ceil(hi + 0.5)
    X = lambda v: L + v / hi * (R - L)
    pitch, bh, top = 24, 15, 34
    b, desc = [], []
    y = top
    group = None
    rows = []
    for g, label, v in OVERVIEW:
        if g != group:
            if group is not None:
                y += 10
            b.append('<text class="nj-charts-panel" x="%g" y="%g">%s</text>' % (8, y + 12, esc(g)))
            y += 22
            group = g
        rows.append((label, v, y))
        y += pitch
    axis_y = y + 2
    for t in range(1, hi + 1):
        b.append('<line class="nj-charts-grid" x1="%g" y1="%g" x2="%g" y2="%g"/>' % (X(t), top, X(t), axis_y))
        b.append('<text class="nj-charts-tick" x="%g" y="%g">%d%s</text>' % (X(t), axis_y + 16, t, TIMES))
    for label, v, yy in rows:
        b.append('<text class="nj-charts-rowlabel nj-charts-tick--r" x="%g" y="%g" text-anchor="end">%s</text>' % (L - 8, yy + bh - 3, esc(label)))
        b.append('<path class="nj-charts-c1" d="%s"><title>%s: %s</title></path>' % (hbar(X(0), X(v), yy, bh), esc(label), fx(v)))
        b.append('<text class="nj-charts-val" x="%g" y="%g">%s</text>' % (X(v) + 5, yy + bh - 3, fx(v)))
        desc.append("%s %s" % (label, fx(v).replace(TIMES, "x")))
    b.append('<line class="nj-charts-ref" x1="%g" y1="%g" x2="%g" y2="%g"/>' % (X(1), top, X(1), axis_y))
    b.append('<line class="nj-charts-zero" x1="%g" y1="%g" x2="%g" y2="%g"/>' % (X(0), top, X(0), axis_y))
    b.append('<text class="nj-charts-note" x="%g" y="%g">speedup over 3.12.0 (the line at 1%s is 3.12.0)</text>' % (L, 18, TIMES))
    write("perf_blog_overview.svg", W, axis_y + 28, "nj-charts--blog", "nj-blog-overview",
          "Speedup of 3.13.0 over 3.12.0 per workload, Apple M1 Max, Apple clang",
          "Horizontal bars, longer is faster. " + "; ".join(desc) + ".", b)


# ---------- timeline: one panel per workload ----------
# (column in perf_timeline.csv, panel title, [PR numbers to label])
TIMELINE = [
    ("parse_citm", "parse() citm_catalog.json", [5234, 5283, 5592, 5809, 5810, 5882]),
    ("parse_canada", "parse() canada.json", [5234, 5283, 5617, 5738, 5851, 5882]),
    ("accept_twitter", "accept() twitter.json", [5234, 5283, 5592, 5809, 5810, 5853]),
    ("parse_twitter_ifstream", "parse() twitter.json, std::ifstream", [5828, 5884]),
    ("dump_twitter", "dump() twitter.json", [5285, 5738, 5878, 5883]),
    ("dump_canada", "dump() canada.json", [5285, 5634]),
    ("from_cbor_twitter", "from_cbor() twitter", [5233, 5501, 5185, 5746]),
    ("to_cbor_twitter", "to_cbor() twitter", [5328, 5824, 5885]),
]
MONTHS = [("2025-04", "3.12.0"), ("2026-09", "Sep 2026"), ("2026-10", "Oct")]


def timeline():
    rows = list(csv.DictReader((HERE / "data" / "perf_timeline.csv").open()))
    n = len(rows)
    W, H = 340, 252
    L, R, T, B = 44, 330, 62, 208
    for col, title, labels in TIMELINE:
        vals = [float(r[col]) if r[col] else None for r in rows]
        base = vals[0]
        rel = [base / v if v else None for v in vals]   # speedup over 3.12.0
        hi = max(x for x in rel if x)
        top = 2 ** math.ceil(math.log2(hi * 1.3))
        Y = lambda s: B - math.log2(s) / math.log2(top) * (B - T)
        X = lambda i: L + i / (n - 1) * (R - L)
        b = ['<text class="nj-charts-panel" x="%g" y="18">%s</text>' % (8, esc(title))]
        t = 1
        while t <= top:
            b.append('<line class="nj-charts-grid" x1="%g" y1="%g" x2="%g" y2="%g"/>' % (L, Y(t), R, Y(t)))
            b.append('<text class="nj-charts-tick nj-charts-tick--r" x="%g" y="%g">%d%s</text>' % (L - 6, Y(t) + 4, t, TIMES))
            t *= 2
        # month ticks: first commit of the month
        seen = set()
        for i, r in enumerate(rows):
            m = r["date"][:7]
            for key, name in MONTHS:
                if m == key and key not in seen:
                    seen.add(key)
                    b.append('<line class="nj-charts-axis" x1="%g" y1="%g" x2="%g" y2="%g"/>' % (X(i), B, X(i), B + 4))
                    b.append('<text class="nj-charts-tick" x="%g" y="%g">%s</text>' % (X(i), B + 17, name))
        # a step line: each commit's value holds until the next commit
        pts, prev = [], None
        for i, s in enumerate(rel):
            if s is None:
                continue
            if prev is not None:
                pts.append("%.1f,%.1f" % (X(i), Y(prev)))
            pts.append("%.1f,%.1f" % (X(i), Y(s)))
            prev = s
        b.append('<polyline class="nj-charts-json" points="%s"/>' % " ".join(pts))
        # labels for named steps: a dot at the commit and its PR number above it; PRs a few commits apart share a
        # label, and a label that would overlap one already placed moves up
        groups = []
        for pr in labels:
            i = next(k for k, r in enumerate(rows) if r["pr"] == str(pr))
            if groups and X(i) - X(groups[-1][-1][1]) < 6:
                groups[-1].append((pr, i))
            else:
                groups.append([(pr, i)])
        # labels in two rows above the plot, each with a guide down to its dot
        placed = []
        for g in groups:
            i = g[-1][1]
            x, y = X(i), Y(rel[i])
            for pr, k in g:
                b.append('<circle class="nj-charts-json-dot" cx="%.1f" cy="%.1f" r="3.5"><title>#%s: %s</title></circle>'
                         % (X(k), Y(rel[k]), pr, fx(rel[k])))
            text = ", ".join("#%s" % pr for pr, _ in g)
            w = 7.2 * len(text)
            tx = min(max(x, L + w / 2), R - w / 2)
            row = 0
            while any(r == row and abs(tx - px) < (w + pw) / 2 + 4 for px, r, pw in placed):
                row += 1
            placed.append((tx, row, w))
            ty = 50 - 13 * row
            b.append('<line class="nj-charts-grid" stroke-dasharray="2 2" x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f"/>' % (x, ty + 4, x, y - 5))
            b.append('<text class="nj-charts-note" x="%.1f" y="%.1f" text-anchor="middle">%s</text>' % (tx, ty, text))
        b.append('<line class="nj-charts-axis" x1="%g" y1="%g" x2="%g" y2="%g"/>' % (L, B, R, B))
        final = rel[-1]
        desc = ("%s: speedup over 3.12.0 at each of %d commits, ending at %s. Labeled steps: %s."
                % (title, n, fx(final).replace(TIMES, "x"), ", ".join("#%s" % p for p in labels)))
        write("perf_blog_timeline_%s.svg" % col, W, H, "nj-charts--timeline", "nj-blog-tl-" + col,
              "%s: speedup over 3.12.0 by commit" % title, desc, b)


# ---------- cliffs: 3.12.0 and 3.13.0 times on a log axis ----------
# (operation, 3.12.0 ms, 3.13.0 ms), copied from the table in "Fix the algorithm first"
CLIFFS = [
    ("diff() 64k numbers vs []", 4102, 9.98),
    ("diff() 20k objects vs half", 119, 3.85),
    ("parse() callback, 32k objects", 1334, 11.5),
    ("< nested 24 deep", 62.6, 0.002),
    ("< citm, 10x", 274, 3.81),
    ("flatten() citm, ordered_json", 253, 1.37),
    ("to_bson() 200 deep, 100x", 19.5, 0.566),
    ("push_back() 100k, diagnostics", 1514, 4.98),
    ("at(i) 10k, diagnostics", 43.2, 0.081),
]


def cliffs():
    W, L, R = 600, 250, 585
    lo, hi = -3, 4   # 1 µs .. 10 s, in log10 ms
    X = lambda ms: L + (math.log10(ms) - lo) / (hi - lo) * (R - L)
    top, pitch = 40, 34
    b, desc = [], []
    axis_y = top + pitch * len(CLIFFS) - 10
    for e in range(lo, hi + 1):
        b.append('<line class="nj-charts-grid" x1="%g" y1="%g" x2="%g" y2="%g"/>' % (X(10 ** e), top - 10, X(10 ** e), axis_y))
        lab = {-3: "1 µs", -2: "10 µs", -1: "0.1 ms", 0: "1 ms", 1: "10 ms", 2: "0.1 s", 3: "1 s", 4: "10 s"}[e]
        b.append('<text class="nj-charts-tick" x="%g" y="%g">%s</text>' % (X(10 ** e), axis_y + 16, lab))
    b.append('<circle class="nj-charts-ojson-dot" cx="%g" cy="14" r="5"/><text class="nj-charts-leg" x="%g" y="18.5">3.12.0</text>' % (L, L + 10))
    b.append('<circle class="nj-charts-json-dot" cx="%g" cy="14" r="5"/><text class="nj-charts-leg" x="%g" y="18.5">3.13.0</text>' % (L + 80, L + 90))
    for i, (op, old, new) in enumerate(CLIFFS):
        y = top + i * pitch + 8
        b.append('<text class="nj-charts-rowlabel" x="%g" y="%g" text-anchor="end">%s</text>' % (L - 10, y + 4, esc(op)))
        b.append('<line class="nj-charts-axis" x1="%g" y1="%g" x2="%g" y2="%g"/>' % (X(new), y, X(old), y))
        b.append('<circle class="nj-charts-ojson-dot" cx="%g" cy="%g" r="5"><title>%s, 3.12.0: %g ms</title></circle>' % (X(old), y, esc(op), old))
        b.append('<circle class="nj-charts-json-dot" cx="%g" cy="%g" r="5"><title>%s, 3.13.0: %g ms</title></circle>' % (X(new), y, esc(op), new))
        b.append('<text class="nj-charts-factor" x="%g" y="%g">%s</text>' % ((X(old) + X(new)) / 2, y - 7, fx(old / new)))
        desc.append("%s: %g ms to %g ms" % (op, old, new))
    write("perf_blog_cliffs.svg", W, axis_y + 28, "nj-charts--blog", "nj-blog-cliffs",
          "Operations that grew quadratically or worse: time with 3.12.0 and 3.13.0, log scale",
          "Dot plot on a logarithmic time axis. " + "; ".join(desc) + ".", b)


# ---------- json_view: parse throughput ----------
# engines and GB/s per file, copied from the table in "Build a different data structure"
VIEW_FILES = ["twitter.json", "citm_catalog.json", "canada.json", "jeopardy.json"]
VIEW_BYTES = [631514, 1727204, 2251051, 55554625]
VIEW_US = [   # (engine, css class, [µs per file])
    ("json_document", "nj-charts-c1", [181.7, 359.9, 959.5, 22687]),
    ("yyjson", "nj-charts-c2", [192.0, 478.1, 1489, 30528]),
    ("simdjson DOM", "nj-charts-c3", [216.4, 490.2, 2098, 26875]),
    ("Boost.JSON", "nj-charts-c4", [866.0, 1480, 2501, 88900]),
    ("json::parse", "nj-charts-c5", [1368, 2409, 5890, 167664]),
]
VIEW = [(e, c, [n / (t * 1000) for n, t in zip(VIEW_BYTES, us)]) for e, c, us in VIEW_US]   # GB/s


def view():
    W, L, R = 580, 142, 545
    hi = max(max(v) for _, _, v in VIEW)
    hi = math.ceil(hi * 2) / 2
    X = lambda v: L + v / hi * (R - L)
    bh, gap = 11, 2
    top = 44
    group_h = len(VIEW) * (bh + gap) + 14
    b, desc = [], []
    x = 8
    for j, (eng, cls, _) in enumerate(VIEW):
        b.append('<rect class="%s" x="%g" y="10" width="12" height="12" rx="3"/>' % (cls, x))
        b.append('<text class="nj-charts-leg" x="%g" y="20.5">%s</text>' % (x + 18, esc(eng)))
        x += 18 + 7.4 * len(eng) + 16
    axis_y = top + group_h * len(VIEW_FILES)
    t = 0.5
    while t <= hi + 1e-9:
        b.append('<line class="nj-charts-grid" x1="%g" y1="%g" x2="%g" y2="%g"/>' % (X(t), top - 4, X(t), axis_y))
        b.append('<text class="nj-charts-tick" x="%g" y="%g">%g</text>' % (X(t), axis_y + 16, t))
        t += 0.5
    b.append('<text class="nj-charts-tick" x="%g" y="%g">GB/s, longer is faster</text>' % ((L + R) / 2, axis_y + 34))
    for i, f in enumerate(VIEW_FILES):
        y0 = top + i * group_h
        b.append('<text class="nj-charts-rowlabel" x="%g" y="%g" text-anchor="end">%s</text>' % (L - 8, y0 + group_h / 2, esc(f)))
        for j, (eng, cls, vals) in enumerate(VIEW):
            y = y0 + j * (bh + gap)
            b.append('<path class="%s" d="%s"><title>%s, %s: %.2f GB/s</title></path>' % (cls, hbar(X(0), X(vals[i]), y, bh), esc(eng), esc(f), vals[i]))
            b.append('<text class="nj-charts-val" x="%g" y="%g">%.2f</text>' % (X(vals[i]) + 4, y + bh - 1.5, vals[i]))
            desc.append("%s %s %.2f GB/s" % (f, eng, vals[i]))
    b.append('<line class="nj-charts-zero" x1="%g" y1="%g" x2="%g" y2="%g"/>' % (X(0), top - 4, X(0), axis_y))
    write("perf_blog_view.svg", W, axis_y + 44, "nj-charts--blog", "nj-blog-view",
          "Parse throughput of json_document, yyjson, simdjson's DOM, Boost.JSON and json::parse, Apple M1 Max",
          "Grouped horizontal bars in GB/s. " + "; ".join(desc) + ".", b)


if __name__ == "__main__":
    swar()
    if OVERVIEW:
        overview()
    if TIMELINE:
        timeline()
    if CLIFFS:
        cliffs()
    if VIEW:
        view()
