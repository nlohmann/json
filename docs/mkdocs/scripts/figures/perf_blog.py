"""Draws the figures of home/blog/how_3_13_0_got_faster.md as inline SVGs into docs/images/.

Generated files:

- perf_blog_overview.svg: speedup of 3.13.0 over 3.12.0 per workload (Google Benchmark suite)
- perf_blog_distribution.svg: how many of the suite's benchmarks got how much faster (data/perf_suite.csv)
- perf_blog_timeline_<workload>.svg: speedup over 3.12.0 of eight workloads at every develop commit that changed
  json.hpp or json_view.hpp since 3.12.0, one panel each
- perf_blog_swar.svg: the eight-byte string test on one word of input
- perf_blog_overlap.svg: writing a short string with two overlapping 16-byte loads and stores
- perf_blog_digits.svg: converting eight ASCII digits with three multiplications
- perf_blog_cliffs.svg: operations that were quadratic or worse, 3.12.0 against 3.13.0 (log scale)
- perf_blog_heldout.svg: validate on the 19 files we didn't tune on, json_document against the fastest library per
  file (data/perf_heldout_validate.json)
- perf_blog_usecases_<platform>.svg: libraries x use cases, time relative to the fastest fully validating library
  (data/perf_usecases_<platform>.json); perf_blog_tables.py prints the tables of the appendix from the same data

The numbers are copied from the tables of the post (the timeline from data/perf_timeline.csv, which
`tests/benchmarks/history/history.py summarize` writes); the tables stay on the page as the accessible fallback. Update both together.
Like the figures of charts.py, the SVGs are not images: the page includes their text with
`--8<-- "images/<name>.svg"`, so they follow the colors and fonts of the page (`nj-charts` rules in
docs/css/fig-charts.css, `nj-fig` rules in docs/css/brand.css). Run `python3 scripts/figures/perf_blog.py` from
docs/mkdocs after changing data or drawing, and commit the generated files.
"""
import csv
import html
import json
import math
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE.parents[1] / "docs" / "images"
MINUS = "&#8722;"
TIMES = "&#215;"

# words the abbreviation extension (includes/glossary.md) would wrap in <abbr> inside the SVG text
GLOSSARY = re.findall(r"^\*\[([^\]]+)\]", (HERE.parents[1] / "includes" / "glossary.md").read_text(), re.M)
ABBR = re.compile(r"(?<![\w;])(%s)(?!\w)" % "|".join(sorted(map(re.escape, GLOSSARY), key=len, reverse=True)))


def protect(text):
    return ABBR.sub(lambda m: m.group(1)[0] + "&#8203;" + m.group(1)[1:], text)


def esc(s):
    return html.escape(s, quote=True).replace("&amp;#", "&#")


def esc_md(s):
    """esc() for text with _ or *, which the page's Markdown pass would pair across text elements as emphasis"""
    return esc(s).replace("_", "&#95;").replace("*", "&#42;")


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


def span(b, x0, x1, y, cls, label):
    """a bracket under the cells from x0 to x1, tinted, with a label to its right or inside"""
    b.append('<rect class="%s" fill-opacity=".22" x="%g" y="%g" width="%g" height="22" rx="4"/>' % (cls, x0, y, x1 - x0))
    b.append('<rect class="%s" x="%g" y="%g" width="4" height="22" rx="2"/>' % (cls, x0, y))
    b.append('<rect class="%s" x="%g" y="%g" width="4" height="22" rx="2"/>' % (cls, x1 - 4, y))
    b.append('<text class="fg-code" x="%g" y="%g" text-anchor="middle" style="font-size:14px">%s</text>' % ((x0 + x1) / 2, y + 16, label))


# ---------- short strings: two overlapping 16-byte loads ----------
def overlap():
    text = "profile_link_color"   # a key of twitter.json, 18 bytes
    n = len(text)
    W = 640
    L, cw, top = 40, 31, 34
    X = lambda i: L + i * cw
    b = ['<text class="fg-h" x="%g" y="20">a string of n = %d bytes: too long for one 16-byte vector, too short for a loop</text>' % (L, n)]
    for i, ch in enumerate(text):
        both = n - 16 <= i < 16
        b.append('<rect class="fg-cell" x="%g" y="%g" width="%g" height="36" rx="4"/>' % (X(i), top, cw - 4))
        if both:
            b.append('<rect class="nj-charts-c3" fill-opacity=".3" x="%g" y="%g" width="%g" height="36" rx="4"/>' % (X(i), top, cw - 4))
        b.append('<text class="fg-code" x="%g" y="%g" text-anchor="middle">%s</text>' % (X(i) + (cw - 4) / 2, top + 24, esc_md(ch)))
    for i in (0, n - 16, 15, n - 1):
        b.append('<text class="nj-charts-tick" x="%g" y="%g">%d</text>' % (X(i) + (cw - 4) / 2, top + 52, i))
    y = top + 66
    span(b, X(0), X(15) + cw - 4, y, "nj-charts-c1", "a = load 16 bytes at p")
    span(b, X(n - 16), X(n - 1) + cw - 4, y + 30, "nj-charts-c2", "b = load 16 bytes at p + n " + MINUS + " 16")
    y += 82
    b.append('<text class="fg-note fg-note--l" x="%g" y="%g">Both loads lie inside the string, and together they cover all of it; bytes %d to 15 are in both.</text>' % (L, y, n - 16))
    b.append('<text class="fg-note fg-note--l" x="%g" y="%g">Test a and b for a quote, a backslash, a control character or 0x7F: none, so write</text>' % (L, y + 22))
    b.append('<text class="fg-code" x="%g" y="%g">store a at d, store b at d + n %s 16</text>' % (L, y + 52, MINUS))
    b.append('<text class="fg-note fg-note--l" x="%g" y="%g">The second store writes bytes %d to 15 again, with the same values. For any n from 16 to 32:</text>' % (L, y + 80, n - 16))
    b.append('<text class="fg-note fg-note--l" x="%g" y="%g">two loads, one test, two stores, no loop and no branch on the length.</text>' % (L, y + 98))
    write("perf_blog_overlap.svg", W, y + 112, "nj-charts--swar", "nj-blog-overlap",
          "Writing an 18-byte string with two overlapping 16-byte loads and stores",
          "The 18 bytes of profile_link_color. Load a covers bytes 0 to 15, load b covers bytes 2 to 17, so bytes 2 to 15 "
          "are in both. Neither contains a byte that needs escaping, so a is stored at the destination and b 2 bytes "
          "later; the second store writes bytes 2 to 15 again with the same values. This works for any length from 16 to "
          "32 bytes without a loop.", b)


# ---------- eight digits at a time: three multiplications ----------
def digits():
    W = 600
    L, cw, h = 40, 64, 34
    X = lambda i: L + i * cw
    steps = [
        ("eight ASCII digits in one 64-bit word (byte 0 is the lowest)", 1, list("12345678"), True),
        ("& 0x0F0F0F0F0F0F0F0F: one digit value per byte", 1, list("12345678"), False),
        ("× (10 · 2⁸ + 1) >> 8, every second byte kept: two digits per 16 bits", 2, ["12", "34", "56", "78"], False),
        ("× (100 · 2¹⁶ + 1) >> 16, every second lane kept: four digits per 32 bits", 4, ["1234", "5678"], False),
        ("× (10000 · 2³² + 1) >> 32: the value", 8, ["12345678"], False),
    ]
    b = []
    y = 20
    for k, (head, width, cells, ascii_) in enumerate(steps):
        b.append('<text class="fg-h" x="%g" y="%g">%s</text>' % (L, y, esc(head)))
        for j, c in enumerate(cells):
            x = X(j * width)
            b.append('<rect class="fg-cell" x="%g" y="%g" width="%g" height="%g" rx="4"/>' % (x, y + 10, width * cw - 6, h))
            if k == len(steps) - 1:
                b.append('<rect class="nj-charts-c1" fill-opacity=".25" x="%g" y="%g" width="%g" height="%g" rx="4"/>' % (x, y + 10, width * cw - 6, h))
            b.append('<text class="fg-code" x="%g" y="%g" text-anchor="middle">%s</text>' % (x + (width * cw - 6) / 2, y + 10 + 23, esc(c)))
            if ascii_:
                b.append('<text class="nj-charts-tick" x="%g" y="%g">0x%02X</text>' % (x + (width * cw - 6) / 2, y + h + 26, ord(c)))
        y += h + (58 if ascii_ else 40)
    b.append('<text class="fg-note fg-note--l" x="%g" y="%g">Each step combines neighboring lanes, in all lanes of the word at once:</text>' % (L, y - 8))
    b.append('<text class="fg-note fg-note--l" x="%g" y="%g">three multiplications instead of eight, and no branch.</text>' % (L, y + 10))
    write("perf_blog_digits.svg", W, y + 22, "nj-charts--swar", "nj-blog-digits",
          "Converting eight ASCII digits to their value with three multiplications",
          "The text 12345678 as one word. Masking gives the digit values 1 to 8, one per byte. Multiplying by 10 times 2 to "
          "the 8 plus 1 and shifting gives 12, 34, 56 and 78 in 16-bit lanes; multiplying by 100 times 2 to the 16 plus 1 "
          "gives 1234 and 5678 in 32-bit lanes; multiplying by 10000 times 2 to the 32 plus 1 gives 12345678.", b)


# ---------- overview: speedup per workload (Google Benchmark rows, 3.12.0 time / 3.13.0 time) ----------
# (group, label, speedup), copied from the table "The short version"
OVERVIEW = [
    ("Parsing", "twitter.json", 3.14),
    ("Parsing", "citm_catalog.json", 4.25),
    ("Parsing", "canada.json", 3.35),
    ("Parsing", "canada.json, indented", 6.51),
    ("Parsing", "citm, ordered_json", 6.85),
    ("Parsing", "twitter, std::ifstream", 2.50),
    ("Parsing", "citm, FILE*", 4.74),
    ("Parsing", "citm, accept()", 7.07),
    ("Writing", "dump() twitter", 6.70),
    ("Writing", "dump() canada", 2.98),
    ("Writing", "dump(4) citm", 4.70),
    ("Writing", "to_cbor() twitter", 4.59),
    ("Reading CBOR", "twitter, memory", 3.39),
    ("Reading CBOR", "twitter, FILE*", 6.59),
    ("Values", "diff() canada", 10.46),
    ("Values", "iterate canada", 2.73),
    ("Values", "copy + destroy citm", 1.13),
    ("Values", "== citm", 1.06),
]


def overview():
    W, L, R = 560, 190, 520
    hi = max(v for _, _, v in OVERVIEW)
    hi = math.ceil(hi + 0.5)
    X = lambda v: L + v / hi * (R - L)
    pitch, bh, top = 24, 15, 8
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
    b.append('<text class="nj-charts-tick" x="%g" y="%g">speedup over 3.12.0 (3.12.0 = 1%s), more is better</text>'
             % ((L + R) / 2, axis_y + 34, TIMES))
    write("perf_blog_overview.svg", W, axis_y + 44, "nj-charts--blog", "nj-blog-overview",
          "Speedup of 3.13.0 over 3.12.0 per workload, Apple M1 Max, Apple clang",
          "Horizontal bars of the speedup, more is better. " + "; ".join(desc) + ".", b)


# ---------- distribution: how many of the suite's benchmarks got how much faster ----------
# bins of the speedup (3.12.0 time / 3.13.0 time) over all rows of data/perf_suite.csv
BINS = [(0, 1, "below 1" + TIMES), (1, 1.5, "1 to 1.5" + TIMES), (1.5, 2, "1.5 to 2" + TIMES),
        (2, 3, "2 to 3" + TIMES), (3, 5, "3 to 5" + TIMES), (5, 10, "5 to 10" + TIMES), (10, 1e9, "10" + TIMES + " or more")]


def distribution():
    rows = list(csv.DictReader((HERE / "data" / "perf_suite.csv").open()))
    s = sorted(float(r["speedup"]) for r in rows)
    n = len(s)
    counts = [sum(lo <= v < hi for v in s) for lo, hi, _ in BINS]
    geo = math.exp(sum(math.log(v) for v in s) / n)
    med = (s[(n - 1) // 2] + s[n // 2]) / 2
    W, H = 560, 250
    L, R, T, B = 52, 548, 16, 196
    hi = 10 * math.ceil(max(counts) / 10 + 0.4)
    Y = lambda c: B - c / hi * (B - T)
    slot = (R - L) / len(BINS)
    b, desc = [], []
    for t in range(0, hi + 1, 20):
        b.append('<line class="nj-charts-grid" x1="%g" y1="%g" x2="%g" y2="%g"/>' % (L, Y(t), R, Y(t)))
        b.append('<text class="nj-charts-tick nj-charts-tick--r" x="%g" y="%g">%d</text>' % (L - 6, Y(t) + 4, t))
    for k, ((lo, _, label), c) in enumerate(zip(BINS, counts)):
        x = L + k * slot + 8
        w = slot - 16
        cls = "nj-charts-c2" if lo < 1 else "nj-charts-c1"
        b.append('<rect class="%s" x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="3"><title>%s: %d</title></rect>'
                 % (cls, x, Y(c), w, B - Y(c), label, c))
        b.append('<text class="nj-charts-val" x="%.1f" y="%.1f" text-anchor="middle">%d</text>' % (x + w / 2, Y(c) - 5, c))
        b.append('<text class="nj-charts-tick" x="%.1f" y="%.1f">%s</text>' % (x + w / 2, B + 16, label))
        desc.append("%s: %d" % (label.replace(TIMES, "x"), c))
    b.append('<line class="nj-charts-axis" x1="%g" y1="%g" x2="%g" y2="%g"/>' % (L, B, R, B))
    b.append('<text class="nj-charts-tick" x="%g" y="%g">speedup over 3.12.0, more is better</text>' % ((L + R) / 2, H - 10))
    b.append('<text class="nj-charts-tick" transform="rotate(-90)" x="%g" y="14">number of benchmarks</text>' % (-(T + B) / 2))
    print("distribution: median %s, geometric mean %s" % (fx(med), fx(geo)))
    write("perf_blog_distribution.svg", W, H, "nj-charts--blog", "nj-blog-dist",
          "Speedup of 3.13.0 over 3.12.0 for all %d benchmarks of the suite" % n,
          "Bars counting the benchmarks per speedup range: " + "; ".join(desc)
          + ". Median %s, geometric mean %s." % (fx(med).replace(TIMES, "x"), fx(geo).replace(TIMES, "x")), b)


# ---------- timeline: one panel per workload ----------
# (column in perf_timeline.csv, panel title, [(PR, label)]): each labeled step shows the number of the theme that
# explains it ("U" for the UTF-8 check of the binary readers that came and went); the appendix maps steps to PRs
TIMELINE = [
    ("parse_citm", "parse() citm_catalog.json", [(5234, "4"), (5283, "1"), (5592, "4"), (5809, "4"), (5810, "2"), (5882, "4")]),
    ("parse_canada", "parse() canada.json", [(5234, "4"), (5283, "1"), (5617, "3"), (5738, "3"), (5851, "3"), (5882, "4")]),
    ("accept_twitter", "accept() twitter.json", [(5234, "4"), (5283, "1"), (5592, "4"), (5809, "4"), (5810, "2"), (5853, "2")]),
    ("parse_twitter_ifstream", "parse() twitter.json, std::ifstream", [(5828, "1"), (5884, "1")]),
    ("dump_twitter", "dump() twitter.json", [(5285, "6"), (5738, "2"), (5878, "2"), (5883, "2")]),
    ("dump_canada", "dump() canada.json", [(5285, "6"), (5634, "3")]),
    ("from_cbor_twitter", "from_cbor() twitter", [(5233, "1"), (5501, "4"), (5185, "U"), (5746, "U")]),
    ("to_cbor_twitter", "to_cbor() twitter", [(5328, "4"), (5824, "6"), (5885, "6")]),
]
MONTHS = [("2025-04", "3.12.0"), ("2026-09", "Sep 2026"), ("2026-10", "Oct")]


def timeline():
    rows = list(csv.DictReader((HERE / "data" / "perf_timeline.csv").open()))
    n = len(rows)
    W, H = 340, 270
    L, R, T, B = 44, 330, 66, 208
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
        for pr, lab in labels:
            i = next(k for k, r in enumerate(rows) if r["pr"] == str(pr))
            if groups and X(i) - X(groups[-1][-1][1]) < 6:
                groups[-1].append((pr, i, lab))
            else:
                groups.append([(pr, i, lab)])
        # labels in two rows above the plot, each with a guide down to its dot
        placed = []
        for g in groups:
            i = g[-1][1]
            x, y = X(i), Y(rel[i])
            for pr, k, lab in g:
                b.append('<circle class="nj-charts-json-dot" cx="%.1f" cy="%.1f" r="3.5"><title>#%s: %s</title></circle>'
                         % (X(k), Y(rel[k]), pr, fx(rel[k])))
            marks = list(dict.fromkeys(lab for _, _, lab in g))
            w = 18 * len(marks) - 3
            tx = min(max(x, L + w / 2), R - w / 2)
            row = 0
            while any(r == row and abs(tx - px) < (w + pw) / 2 + 4 for px, r, pw in placed):
                row += 1
            placed.append((tx, row, w))
            ty = 46 - 18 * row   # the center of the badges
            b.append('<line class="nj-charts-grid" stroke-dasharray="2 2" x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f"/>' % (x, ty + 8, x, y - 5))
            for k, mark in enumerate(marks):
                cx = tx - w / 2 + 7.5 + 18 * k
                b.append('<circle class="nj-theme-dot%s" cx="%.1f" cy="%.1f" r="7.5"/>' % ("" if mark.isdigit() else " nj-theme-dot--other", cx, ty))
                b.append('<text class="nj-theme-num" x="%.1f" y="%.1f" text-anchor="middle">%s</text>' % (cx, ty + 4, mark))
        b.append('<line class="nj-charts-axis" x1="%g" y1="%g" x2="%g" y2="%g"/>' % (L, B, R, B))
        b.append('<text class="nj-charts-note" x="%g" y="%g">speedup over 3.12.0 (log scale), more is better</text>' % (8, H - 8))
        final = rel[-1]
        desc = ("%s: speedup over 3.12.0 at each of %d commits, ending at %s. Labeled steps, by theme: %s."
                % (title, n, fx(final).replace(TIMES, "x"), ", ".join(lab for _, lab in labels)))
        write("perf_blog_timeline_%s.svg" % col, W, H, "nj-charts--timeline", "nj-blog-tl-" + col,
              "%s: speedup over 3.12.0 by commit" % title, desc, b)


# ---------- cliffs: 3.12.0 and 3.13.0 times on a log axis ----------
# (operation, 3.12.0 ms, 3.13.0 ms), copied from the table in "Fix the algorithm first"
CLIFFS = [
    ("diff() 64k numbers vs []", 4237, 10.8),
    ("diff() 20k objects vs half", 122, 4.13),
    ("parse() callback, 32k objects", 1398, 12.1),
    ("operator< nested 24 deep", 64.4, 0.002),
    ("operator< citm, 10x", 284, 3.94),
    ("flatten() citm, ordered_json", 271, 1.45),
    ("to_bson() 200 deep, 100x", 20.3, 0.352),
    ("push_back() 100k, diagnostics", 1589, 5.32),
    ("at(i) 10k, diagnostics", 45.9, 0.088),
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
    b.append('<text class="nj-charts-tick" x="%g" y="%g">runtime (log scale), less is better</text>' % ((L + R) / 2, axis_y + 34))
    b.append('<defs><marker id="nj-blog-cliffs-head" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" '
             'orient="auto"><path class="nj-charts-head" d="M0 0 L10 5 L0 10 z"/></marker></defs>')
    b.append('<circle class="nj-charts-ojson-dot" cx="%g" cy="14" r="5"/><text class="nj-charts-leg" x="%g" y="18.5">3.12.0</text>' % (L, L + 10))
    b.append('<circle class="nj-charts-json-dot" cx="%g" cy="14" r="5"/><text class="nj-charts-leg" x="%g" y="18.5">3.13.0</text>' % (L + 80, L + 90))
    for i, (op, old, new) in enumerate(CLIFFS):
        y = top + i * pitch + 8
        b.append('<text class="nj-charts-rowlabel" x="%g" y="%g" text-anchor="end">%s</text>' % (L - 10, y + 4, esc(op)))
        # an arrow from the old time to the new one, ending just before the new dot
        b.append('<line class="nj-charts-axis" x1="%g" y1="%g" x2="%g" y2="%g" marker-end="url(#nj-blog-cliffs-head)"/>'
                 % (X(old) - 6, y, X(new) + 7, y))
        b.append('<circle class="nj-charts-ojson-dot" cx="%g" cy="%g" r="5"><title>%s, 3.12.0: %g ms</title></circle>' % (X(old), y, esc(op), old))
        b.append('<circle class="nj-charts-json-dot" cx="%g" cy="%g" r="5"><title>%s, 3.13.0: %g ms</title></circle>' % (X(new), y, esc(op), new))
        b.append('<text class="nj-charts-factor" x="%g" y="%g">%s</text>' % ((X(old) + X(new)) / 2, y - 7, fx(old / new)))
        desc.append("%s: %g ms to %g ms" % (op, old, new))
    write("perf_blog_cliffs.svg", W, axis_y + 44, "nj-charts--blog", "nj-blog-cliffs",
          "Operations that grew quadratically or worse: time with 3.12.0 and 3.13.0, log scale",
          "Dot plot on a logarithmic time axis, less is better; an arrow leads from each 3.12.0 time to the 3.13.0 time. " + "; ".join(desc) + ".", b)


# ---------- validating the files we didn't tune on, file by file ----------
# data/perf_heldout_validate.json: per platform, file and library the fastest fully validating way of the validate
# use case on the 19 other files of simdjson's jsonexamples (reused parsers not chosen), extracted from
# summarize.py --json of the held-out run
HELDOUT = [("mac", "Apple M1 Max", "nj-charts-json-dot"), ("x86-gcc", "x86-64, GCC 16.2", "nj-charts-ojson-dot")]


def heldout():
    data = json.load((HERE / "data" / "perf_heldout_validate.json").open())
    files = sorted(data["mac"])
    rel, winner = {}, {}
    for plat, _, _ in HELDOUT:
        for f in files:
            libs = data[plat][f]
            # the fastest other library: below 1 json_document is the fastest, and the distance shows by how much
            best = min((l for l in libs if l != "nlohmann json_document"), key=lambda l: libs[l]["us"])
            rel[plat, f] = libs["nlohmann json_document"]["us"] / libs[best]["us"]
            winner[plat, f] = UC_LIBS.get(best, best)
    files.sort(key=lambda f: (rel["x86-gcc", f], rel["mac", f]))
    W, L, R = 620, 262, 486
    lo, hi = 0.4, 1.15
    X = lambda r: L + (r - lo) / (hi - lo) * (R - L)
    top, pitch = 58, 20
    axis_y = top + pitch * len(files)
    b, desc = [], []
    for t in (0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 1.1):
        b.append('<line class="nj-charts-grid" x1="%g" y1="%g" x2="%g" y2="%g"/>' % (X(t), top - 8, X(t), axis_y))
        b.append('<text class="nj-charts-tick" x="%g" y="%g">%.1f%s</text>' % (X(t), axis_y + 16, t, TIMES))
    b.append('<text class="nj-charts-tick" x="%g" y="%g">json&#95;document&#8217;s time / the fastest other library&#8217;s, less is better</text>' % ((L + R) / 2, axis_y + 34))
    x = 8
    for plat, name, cls in HELDOUT:
        b.append('<circle class="%s" cx="%g" cy="14" r="5"/><text class="nj-charts-leg" x="%g" y="18.5">%s</text>' % (cls, x + 5, x + 15, esc_md(name)))
        x += 30 + 7.6 * len(name)
    b.append('<text class="nj-charts-tick nj-charts-tick--l" x="%g" y="%g">next on x86-64</text>' % (R + 14, top - 10))
    for i, f in enumerate(files):
        y = top + i * pitch + 6
        b.append('<text class="nj-charts-rowlabel nj-charts-code" x="%g" y="%g" text-anchor="end">%s</text>' % (L - 10, y + 4, esc_md(f)))
        for k, (plat, name, cls) in enumerate(HELDOUT):
            r = rel[plat, f]
            b.append('<circle class="%s" cx="%.1f" cy="%g" r="4.5"><title>%s, %s: %.2f%s the time of %s</title></circle>'
                     % (cls, X(max(lo, min(r, hi))), y - 3.5 + 7 * k, esc_md(f), esc_md(name), r, TIMES, esc_md(winner[plat, f])))
        w = winner["x86-gcc", f]
        b.append('<text class="nj-charts-tick nj-charts-tick--l%s" x="%g" y="%g">%s</text>'
                 % (" nj-charts-best" if rel["x86-gcc", f] > 1.0005 else "", R + 14, y + 4, esc_md(w)))
        desc.append("%s: Mac %.2f, x86-64 %.2f (%s)" % (f, rel["mac", f], rel["x86-gcc", f], w))
    b.append('<line class="nj-charts-ref" x1="%g" y1="%g" x2="%g" y2="%g"/>' % (X(1), top - 8, X(1), axis_y))
    b.append('<text class="nj-charts-tick" x="%g" y="%g">as fast as the next</text>' % (X(1), top - 14))
    wins = {p: sum(rel[p, f] < 1 for f in files) for p, _, _ in HELDOUT}
    print("heldout: json_document fastest on %s" % wins)
    write("perf_blog_heldout.svg", W, axis_y + 44, "nj-charts--blog", "nj-blog-heldout",
          "Validating 19 files 3.13.0 was not tuned on: json_document's time relative to the fastest other library per file",
          "Dot plot per file, less is better; below 1.0 json_document is the fastest fully validating library. "
          + "; ".join(desc) + ".", b)


# ---------- the price: compile time of two programs against 3.12.0 ----------
# CPU time of the compiler in ms, median of 5 interleaved rounds, C++20, M1 Max (the post's appendix G)
# (3.12.0, 3.13.0, 3.13.0 with a precompiled header, 3.13.0 as a module)
PRICE = [
    ("Apple clang 21, -O0 (debug)", [("count_numbers", 955.0, 1320.5, 688.5, 917.5), ("server_config", 1113.2, 1496.4, 862.6, 1135.5)]),
    ("Apple clang 21, -O2", [("count_numbers", 1393.2, 2081.0, 1458.4, 1684.6), ("server_config", 1753.5, 2545.6, 1925.3, 2168.6)]),
    ("GCC 16, -O0 (debug)", [("count_numbers", 1569.4, 2548.4, 1725.0, 1699.8), ("server_config", 2025.4, 2985.1, 2301.6, 2325.8)]),
    ("GCC 16, -O2", [("count_numbers", 2336.0, 3701.5, 2986.8, 2913.4), ("server_config", 3121.5, 4714.2, 4006.2, 4054.9)]),
]
PRICE_SERIES = [("3.13.0", "nj-charts-c2"), ("3.13.0, precompiled header", "nj-charts-c1"), ("3.13.0, module", "nj-charts-c3")]


def price():
    W, L, R = 600, 150, 560
    lo, hi = -50, 70
    X = lambda pct: L + (pct - lo) / (hi - lo) * (R - L)
    pct = lambda new, old: round((new / old - 1) * 100)
    lab = lambda p: (MINUS + "%d%%" % -p) if p < 0 else "+%d%%" % p
    bh, pitch, gap = 11, 14, 10
    b, desc = [], []
    # the key above the plot
    x = 8
    for name, cls in PRICE_SERIES:
        b.append('<rect class="%s" x="%g" y="6" width="12" height="12" rx="3"/>' % (cls, x))
        b.append('<text class="nj-charts-leg" x="%g" y="16.5">%s</text>' % (x + 18, esc(name)))
        x += 18 + 8.2 * len(name) + 22
    top = 54
    b.append('<text class="nj-charts-tick" x="%g" y="%g">as fast as 3.12.0</text>' % (X(0), top - 8))
    y = top
    for build, progs in PRICE:
        b.append('<text class="nj-charts-panel" x="8" y="%g">%s</text>' % (y + 14, esc(build)))
        y += 24
        y0, at = y, len(b)
        for prog, old, *new in progs:
            b.append('<text class="nj-charts-rowlabel nj-charts-code" x="%g" y="%g" text-anchor="end">%s</text>'
                     % (L - 8, y + 1.5 * pitch + 2, prog))
            for (name, cls), t in zip(PRICE_SERIES, new):
                p = pct(t, old)
                b.append('<path class="%s" d="%s"><title>%s, %s, %s: %s ms against %s ms with 3.12.0 (%s)</title></path>'
                         % (cls, hbar(X(0), X(p), y, bh), prog, esc(build), esc(name), format(round(t), ","), format(round(old), ","), lab(p)))
                if p < 0:
                    b.append('<text class="nj-charts-val" x="%g" y="%g" text-anchor="end">%s</text>' % (X(p) - 5, y + bh - 1.5, lab(p)))
                else:
                    b.append('<text class="nj-charts-val" x="%g" y="%g">%s</text>' % (X(p) + 5, y + bh - 1.5, lab(p)))
                desc.append("%s, %s, %s: %s" % (build, prog, name, lab(p).replace(MINUS, "-")))
                y += pitch
            y += gap - (pitch - bh)
        # the grid behind this panel's bars only, so that it doesn't cross the panel titles
        b[at:at] = ['<line class="nj-charts-grid" x1="%g" y1="%g" x2="%g" y2="%g"/>' % (X(t), y0 - 4, X(t), y - gap + 4)
                    for t in range(lo + 10, hi + 1, 20) if t]
        y += 8
    axis_y = y
    b.append('<line class="nj-charts-ref" x1="%g" y1="%g" x2="%g" y2="%g"/>' % (X(0), top - 2, X(0), axis_y))
    for t in range(lo + 10, hi + 1, 20):
        b.append('<text class="nj-charts-tick" x="%g" y="%g">%s</text>' % (X(t), axis_y + 16, "0" if t == 0 else lab(t)))
    b.append('<text class="nj-charts-tick" x="%g" y="%g">compile time compared with 3.12.0, less is better</text>' % ((L + R) / 2, axis_y + 34))
    write("perf_blog_price.svg", W, axis_y + 44, "nj-charts--blog", "nj-blog-price",
          "Compile time of two programs with 3.13.0, alone, with a precompiled header and as a module, compared with 3.12.0",
          "Horizontal bars of the change in compile time against 3.12.0, less is better. " + "; ".join(desc) + ".", b)


# ---------- use cases: libraries x use cases, relative time ----------
# data/perf_usecases_<platform>.json is written by tests/benchmarks/json_view/others/summarize.py --json
UC_FILES = ["twitter", "citm_catalog", "canada", "jeopardy"]
USE_CASES = [("validate", "validate"), ("sum", "sum"), ("select", "select"),
             ("edit", "edit"), ("minify", "minify"), ("write", "write")]
UC_LIBS = {   # library in the JSON -> row label
    "nlohmann json_document": "nlohmann/json json_document", "nlohmann json": "nlohmann/json json",
    "yyjson": "yyjson", "simdjson": "simdjson", "sonic-cpp": "sonic-cpp", "Glaze": "Glaze", "Boost.JSON": "Boost.JSON",
    "RapidJSON": "RapidJSON", "sonic-rs": "sonic-rs (Rust)", "simd-json": "simd-json (Rust)", "serde_json": "serde_json (Rust)",
}
UC_PLATFORMS = [("mac", "Use cases: time of each library relative to the fastest, Apple M1 Max"),
                ("x86-gcc", "Use cases: time of each library relative to the fastest, x86-64 with GCC 16.2"),
                ("x86-gcc13", "Use cases: time of each library relative to the fastest, x86-64 with GCC 13"),
                ("x86-clang", "Use cases: time of each library relative to the fastest, x86-64 with Clang 23")]
LEVEL_MARK = {"no UTF-8": "U", "partial": "P", "full": ""}
# why a cell is empty (the tooltips of the n/a cells)
NA = {("simdjson", "edit"): "simdjson's documents are read-only: it has no API to change a value and write the result"}


def geomean(xs):
    return math.exp(sum(math.log(x) for x in xs) / len(xs))


WRITING = ("edit", "minify", "write")   # the use cases that write numbers
NUMBER_TEXT = ("source numbers", "raw numbers")   # variants that write each number by copying its text


def normalize_usecases(data):
    """Chooses each library's best variants again with the rules of the post: variants that reuse a parser or document
    across calls are measured but not chosen. Variants that write each number by copying its text instead of formatting
    it (json_document's number_format::source, yyjson's and RapidJSON's raw numbers in edit, minify and write) are not
    chosen as the fully validating way, but as a way that does less, marked "N" like "U" and "P". Skipping the number
    conversion while reading is allowed. Each pick has a "mark": "", or the letters of what it skips"""
    data = json.loads(json.dumps(data))
    rank = {"full": 0, "n/a": 0, "no UTF-8": 1, "partial": 2}
    for uc, files in data.items():
        numtext = lambda k: uc in WRITING and any(w in k for w in NUMBER_TEXT)
        for cell in files.values():
            for e in cell.values():
                vs = [(v["us"], k, v["level"]) for k, v in e["variants"].items() if "reused" not in k]
                full = [v for v in vs if rank[v[2]] == 0 and not numtext(v[1])]
                pick = lambda v: {"us": v[0], "variant": v[1], "level": "full" if rank[v[2]] == 0 else v[2],
                                  "mark": " ".join(m for m in (LEVEL_MARK.get(v[2], ""), "N" if numtext(v[1]) else "") if m)}
                e["best"] = pick(min(full)) if full else None
                e["best_any"] = pick(min(vs))
    return data


FILE_NAMES = {"twitter": "twitter.json", "citm_catalog": "citm_catalog.json", "canada": "canada.json",
              "jeopardy": "jeopardy.json"}
# what a variant that checks less skips, worded as the trade it is (the tooltips of the heatmaps)
CHECKS_LESS = [
    ("simdjson", "On-Demand", "reads lazily: On-Demand reads only what you ask for and steps over the rest by matching brackets"),
    ("simdjson", "minify", "simdjson::minify() only removes whitespace, without parsing the values"),
    ("Glaze", "lazy_json", "reads lazily: lazy_json reads only what you ask for and steps over the rest"),
    ("Glaze", "minify_json", "minify_json only removes whitespace, without parsing the values"),
    ("Glaze", "generic", "accepts trailing garbage after the value: Glaze's default (validate_trailing_whitespace checks it)"),
    ("Glaze", "structs", "reads into structs and steps over fields it doesn't know without checking them "
                         "(validate_skipped checks them too)"),
    ("RapidJSON", "", "trusts UTF-8: RapidJSON's default (kParseValidateEncodingFlag checks it)"),
    ("sonic-cpp", "", "trusts UTF-8: sonic-cpp 1.0.2 doesn't check it"),
    ("serde_json", "", "trusts UTF-8 in the strings it skips (from_slice); strings it reads are checked"),
]
# what a variant that copies number text does (the "N" half of edit, minify and write)
NUMBER_TEXT_TIPS = {
    "nlohmann json_document": "copies each number's text instead of formatting it (number_format::source)",
    "yyjson": "copies each number's text instead of formatting it (YYJSON_READ_NUMBER_AS_RAW)",
    "RapidJSON": "copies each number's text instead of formatting it (kParseNumbersAsStringsFlag)",
}


def checks_less(lib, variant):
    for l, v, text in CHECKS_LESS:
        if l == lib and v in variant:
            return text
    return "checks less"


def usecase_table(data):
    """{library: {use case: cell}}: per library the geometric mean over UC_FILES of its fastest fully validating time
    ("full") and of its fastest time at any level ("alt", only if it is at least 3 % faster), each divided by the best
    such fully validating mean in the use case, so that every file counts equally and the fastest library is 1.00"""
    out = {}
    data = normalize_usecases(data)
    for uc, _ in USE_CASES:
        files = data.get(uc, {})
        if not files:
            continue
        cells = {}
        for lib in UC_LIBS:
            es = [files.get(f, {}).get(lib) for f in UC_FILES]
            if not all(es):
                continue
            full = [e["best"] for e in es]
            alt = [e["best_any"] for e in es]
            cells[lib] = {"full": geomean([b["us"] for b in full]) if all(full) else None, "alt": geomean([a["us"] for a in alt]),
                          "files": [(f, b, a) for f, b, a in zip(UC_FILES, full, alt)]}
        ref = min(c["full"] for c in cells.values() if c["full"])
        for lib, c in cells.items():
            full = c["full"] / ref if c["full"] else None
            alt = c["alt"] / ref
            if full is not None and alt > full * 0.97:
                alt = None
            levels = {a["level"] for _, _, a in c["files"]} if alt is not None else set()
            level = "partial" if "partial" in levels else "no UTF-8" if "no UTF-8" in levels else "full"
            numtext = alt is not None and any("N" in a["mark"].split() for _, _, a in c["files"])
            marks = " ".join(m for m in (LEVEL_MARK[level], "N" if numtext else "") if m)
            out.setdefault(lib, {})[uc] = {"full": full, "alt": alt, "level": level, "marks": marks, "files": c["files"]}
    return out


# cell colors: green for the fastest, gray around twice the time, red for the slowest; the upper bounds of the steps
HEAT_STEPS = [1.15, 1.5, 2.5, 5, float("inf")]
HEAT_LABELS = ["below 1.15", "1.15 to 1.5", "1.5 to 2.5", "2.5 to 5", "5 and more"]


def heat(r):
    return next(i for i, b in enumerate(HEAT_STEPS) if r < b)


def fr(r):
    return "%.2f" % r if r < 9.995 else "%.1f" % r if r < 99.95 else "%.0f" % r


def fus(us):
    return "{:,.0f} µs".format(us) if us >= 100 else "%.1f µs" % us


def tip(lib, uc_label, c, half):
    """the tooltip of a cell: lines separated by newlines (&#10; in the attribute), the first one the heading"""
    if half == "full":
        lines = ["%s · %s" % (UC_LIBS[lib], uc_label),
                 "%s× the time of the fastest library (fully validating)" % fr(c["full"])]
        picks = [(f, b) for f, b, _ in c["files"]]
    else:
        lines = ["%s · %s, checking less" % (UC_LIBS[lib], uc_label),
                 "%s× the time of the fastest fully validating library" % fr(c["alt"])]
        picks = [(f, a) for f, _, a in c["files"]]
    ways = sorted({e["variant"] for _, e in picks})
    if len(ways) == 1:
        lines.append("way: %s" % ways[0])
    for f, e in picks:
        lines.append("%s: %s%s%s" % (FILE_NAMES[f], fus(e["us"]), "" if len(ways) == 1 else " · " + e["variant"],
                                     " (validates fully)" if half == "alt" and e["level"] == "full" else ""))
    if half == "alt":
        seen = []
        for _, e in picks:
            ts = ([checks_less(lib, e["variant"])] if e["level"] != "full" else []) + \
                 ([NUMBER_TEXT_TIPS.get(lib, "copies each number's text instead of formatting it")] if "N" in e["mark"].split() else [])
            for t in ts:
                if t not in seen:
                    seen.append(t)
        lines += seen
    if any("(copy)" in e["variant"] for _, e in picks):
        lines.append("(copy): parses in place, on a copy of the input that is part of the time")
    return "&#10;".join(lines)


def heatmap(platform, title):
    data = json.load((HERE / "data" / ("perf_usecases_%s.json" % platform)).open())
    t = usecase_table(data)
    libs = [l for l in UC_LIBS if l in t]
    score = lambda l: geomean([v["full"] or v["alt"] for v in t[l].values()])   # the mean of the row as shown
    libs.sort(key=score)
    W, L, cw, ch, top = 784, 224, 92, 36, 44
    b, desc = [], []
    for j, (uc, label) in enumerate(USE_CASES):
        b.append('<text class="nj-charts-tick" x="%g" y="%g">%s</text>' % (L + j * cw + cw / 2, top - 10, esc(label)))
    for i, lib in enumerate(libs):
        y = top + i * ch
        cls = "nj-charts-name-json" if lib.startswith("nlohmann") else ""
        b.append('<text class="nj-charts-rowlabel %s" x="%g" y="%g" text-anchor="end">%s</text>' % (cls, L - 8, y + ch / 2 + 4, esc(UC_LIBS[lib])))
        for j, (uc, label) in enumerate(USE_CASES):
            x = L + j * cw
            c = t[lib].get(uc)
            if c is None:
                b.append('<g class="nj-heat-cell" tabindex="0" data-tip="%s">' % esc("%s · %s&#10;%s" % (UC_LIBS[lib], label, NA.get((lib, uc), "the library has no API for this use case"))))
                b.append('<rect class="nj-heat-na" x="%g" y="%g" width="%g" height="%g" rx="3"/>' % (x + 1, y + 1, cw - 2, ch - 2))
                b.append('<text class="nj-charts-tick" x="%g" y="%g">n/a</text>' % (x + cw / 2, y + ch / 2 + 4))
                b.append('</g>')
                desc.append("%s %s: n/a" % (UC_LIBS[lib], label))
                continue
            halves = []
            if c["full"] is not None:
                halves.append(("full", c["full"]))
            if c["alt"] is not None:
                halves.append(("alt", c["alt"]))
            hw = (cw - 2) / len(halves)
            for k, (half, r) in enumerate(halves):
                hx = x + 1 + k * hw
                gap = 1 if len(halves) == 2 else 0
                b.append('<g class="nj-heat-cell" tabindex="0" data-tip="%s">' % esc(tip(lib, label, c, half)))
                b.append('<rect class="nj-heat-%d" x="%g" y="%g" width="%g" height="%g" rx="3"/>'
                         % (heat(r), hx + (gap if k else 0), y + 1, hw - gap, ch - 2))
                cx = hx + hw / 2
                if half == "alt":
                    b.append('<text class="nj-charts-cell" x="%g" y="%g" text-anchor="middle">%s</text>' % (cx, y + 16, fr(r)))
                    b.append('<text class="nj-charts-cell nj-charts-cell--small" x="%g" y="%g" text-anchor="middle">%s</text>'
                             % (cx, y + 29, c["marks"]))
                else:
                    b.append('<text class="nj-charts-cell" x="%g" y="%g" text-anchor="middle">%s</text>' % (cx, y + ch / 2 + 4, fr(r)))
                b.append('</g>')
            if c["full"] is None:   # no fully validating way: the left half stays empty
                pass
            desc.append("%s %s: %s%s" % (UC_LIBS[lib], label, fr(c["full"]) if c["full"] else "no fully validating way",
                                         (" (%s doing less, %s)" % (fr(c["alt"]), c["marks"])) if c["alt"] else ""))
    # the key, set apart from the grid and narrower than its columns, so that it doesn't read as a row of it
    yb = top + len(libs) * ch + 28
    b.append('<text class="nj-charts-tick nj-charts-tick--l" x="8" y="%g">time relative to the fastest fully validating library, less is better</text>' % (yb + 4))
    kw, ky = 76, yb + 14
    for i, lab in enumerate(HEAT_LABELS):
        # each swatch in its own group, so that the ink rule for the strong steps (a sibling selector) stays inside it
        b.append('<g><rect class="nj-heat-%d" x="%g" y="%g" width="%g" height="20" rx="3"/>' % (i, 8 + i * (kw + 4), ky, kw))
        b.append('<text class="nj-charts-cell nj-charts-cell--small" x="%g" y="%g" text-anchor="middle">%s</text></g>' % (8 + i * (kw + 4) + kw / 2, ky + 14, esc(lab)))
    nx = 8 + len(HEAT_LABELS) * (kw + 4) + 12
    b.append('<rect class="nj-heat-na" x="%g" y="%g" width="%g" height="20" rx="3"/>' % (nx, ky, 40))
    b.append('<text class="nj-charts-tick" x="%g" y="%g">n/a</text>' % (nx + 20, ky + 14))
    b.append('<text class="nj-charts-tick nj-charts-tick--l" x="%g" y="%g">no API for it</text>' % (nx + 48, ky + 14))
    write("perf_blog_usecases_%s.svg" % platform, W, ky + 28, "nj-charts--blog nj-charts--heat", "nj-blog-uc-" + platform, title,
          "Table of relative times, libraries by use case. " + "; ".join(desc) + ".", b)


if __name__ == "__main__":
    swar()
    overlap()
    digits()
    heldout()
    if OVERVIEW:
        overview()
    distribution()
    if TIMELINE:
        timeline()
    if CLIFFS:
        cliffs()
    price()
    for platform, title in UC_PLATFORMS:
        if (HERE / "data" / ("perf_usecases_%s.json" % platform)).exists():
            heatmap(platform, title)
