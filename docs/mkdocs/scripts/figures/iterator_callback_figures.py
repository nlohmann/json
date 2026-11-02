"""Draws the parser-callback and iterator illustrations as an inline SVG into docs/images/.

The SVG is not an image: the pages include its text with `--8<-- "images/callback_events.svg, range-begin-end.svg and range-rbegin-rend.svg"`, so it picks up the colours and fonts of the
page (see the `railroad` and `nj-fig` rules in docs/css/brand.css). Run `python3 scripts/figures/iterator_callback_figures.py` from docs/mkdocs after
changing the drawing, and commit the generated file. In SVG text write the word JSON as `J&#8203;SON`, otherwise the
abbreviation extension wraps it in an <abbr> and the text disappears.
"""
import html
from pathlib import Path

OUT = Path(__file__).resolve().parents[2] / "docs" / "images"
CW = 9.6   # JetBrains Mono advance at 16px

def write(name, W, H, cls, tid, title, body, defs=""):
    s = ['<svg class="nj-fig %s" viewBox="0 0 %d %d" role="img" aria-labelledby="%s" xmlns="http://www.w3.org/2000/svg">' % (cls, W, H, tid),
         '<title id="%s">%s</title>' % (tid, html.escape(title).replace('J&amp;#8203;SON', 'J&#8203;SON'))]
    if defs: s.append(defs)
    s += body
    s.append('</svg>')
    open(OUT / name, "w").write("\n".join(s) + "\n")

# ---------- callback events ----------
def callback():
    body, y0, lh = [], 74, 28
    body.append('<text class="fg-h" x="16" y="28">J&#8203;SON to parse</text>')
    body.append('<text class="fg-h" x="320" y="28">callback events</text>')
    lines = [
        (0, [("{", None), (None, "os")]),
        (2, [('"name"', None), (None, "k"), (': "Berlin"', None), (None, "v"), (",", None)]),
        (2, [('"location"', None), (None, "k"), (": [", None), (None, "as")]),
        (4, [("52.519444", None), (None, "v"), (",", None)]),
        (4, [("13.406667", None), (None, "v")]),
        (2, [("]", None), (None, "ae"), (None, "v")]),
        (0, [("}", None), (None, "oe"), (None, "v")]),
    ]
    for i, (indent, parts) in enumerate(lines):
        y = y0 + i * lh
        x = 16 + indent * CW
        for text, ev in parts:
            if text is not None:
                body.append('<text class="fg-code" x="%g" y="%d" xml:space="preserve">%s</text>' % (x, y, html.escape(text)))
                x += CW * len(text)
            else:
                body.append('<circle class="cb-%s" cx="%g" cy="%d" r="5.5"/>' % (ev, x + 10, y - 5))
                x += 20 if text is None else 0
    legend = [("os", "object_start"), ("k", "key"), ("oe", "object_end"), ("as", "array_start"), ("ae", "array_end"), ("v", "value")]
    for i, (ev, label) in enumerate(legend):
        y = 74 + i * 30
        body.append('<circle class="cb-%s" cx="327" cy="%d" r="6"/>' % (ev, y - 5))
        body.append('<text class="fg-code fg-leg" x="344" y="%d">%s</text>' % (y, label))
    write("callback_events.svg", 480, 262, "nj-fig--cb", "fig-cb-title",
          "Example of the parse events a callback sees for the J&#8203;SON text {\"name\": \"Berlin\", \"location\": [52.519444, 13.406667]}: object_start after the opening brace, key after each key, array_start after the opening bracket, value after each value, array_end after the closing bracket, and object_end after the closing brace. Every array and object also produces a value event when it is complete.", body)

# ---------- ranges ----------
BW, GAP, X0 = 30, 4, 30
def cell_x(i): return X0 + i * (BW + GAP)
def cell(i, y, kind):
    c = "fg-cell" + (" fg-cell--end" if kind == "end" else "")
    return '<rect class="%s" x="%d" y="%d" width="%d" height="30" rx="5"/>' % (c, cell_x(i), y, BW)
def pill(cx, y, label, W, label_w):
    x = max(4, min(W - 4 - label_w, cx - label_w / 2))
    return ['<rect class="fg-pill" x="%g" y="%d" width="%d" height="24" rx="6"/>' % (x, y, label_w),
            '<text class="fg-pilltext" x="%g" y="%d">%s</text>' % (x + label_w / 2, y + 16.5, label)]
def arrow(x, ya, yb, mid, dashed=False):
    return '<line class="fg-arrow%s" x1="%g" y1="%g" x2="%g" y2="%g" marker-end="url(#%s)"/>' % (" fg-arrow--dash" if dashed else "", x, ya, x, yb, mid)

def ranges1():
    W, H, mid = 600, 150, "fig-be-arrow"
    defs = '<defs><marker id="%s" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path class="fg-head" d="M0 1 L10 5 L0 9 z"/></marker></defs>' % mid
    body = []
    for i in range(15): body.append(cell(i, 62, "elem"))
    body.append(cell(15, 62, "end"))
    body += pill(cell_x(0) + BW / 2, 8, "begin", W, 60); body.append(arrow(cell_x(0) + BW / 2, 32, 60, mid))
    body += pill(cell_x(15) + BW / 2, 8, "end", W, 48); body.append(arrow(cell_x(15) + BW / 2, 32, 60, mid))
    body.append('<text class="fg-note fg-note--r" x="%d" y="132">Past-the-last element</text>' % (cell_x(15) + BW / 2 - 18))
    body.append(arrow(cell_x(15) + BW / 2, 124, 96, mid))
    write("range-begin-end.svg", W, H, "nj-fig--range", "fig-be-title",
          "A row of fifteen elements followed by a dashed past-the-last position. begin() points to the first element and end() points to the past-the-last position.", body, defs)

def ranges2():
    W, H, mid = 600, 236, "fig-rbe-arrow"
    defs = '<defs><marker id="%s" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path class="fg-head" d="M0 1 L10 5 L0 9 z"/></marker></defs>' % mid
    body = []
    ytop, ybot = 62, 144
    body.append(cell(0, ytop, "end"))
    for i in range(1, 16): body.append(cell(i, ytop, "elem"))
    for i in range(15): body.append(cell(i, ybot, "elem"))
    body.append(cell(15, ybot, "end"))
    body += pill(cell_x(0) + BW / 2, 8, "rend", W, 52); body.append(arrow(cell_x(0) + BW / 2, 32, 60, mid))
    body += pill(cell_x(15) + BW / 2, 8, "rbegin", W, 68); body.append(arrow(cell_x(15) + BW / 2, 32, 60, mid))
    body.append('<text class="fg-note fg-note--l" x="%d" y="24">Reverse past-the-last element</text>' % (cell_x(0) + BW / 2 + 36))
    for col in (0, 15):
        x = cell_x(col) + BW / 2
        body.append('<line class="fg-arrow fg-arrow--dash" x1="%g" y1="94" x2="%g" y2="%d"/>' % (x, x, ybot - 2))
    body.append('<text class="fg-note" x="300" y="123">A reverse iterator stores an iterator to the next element</text>')
    body.append('<text class="fg-note" x="300" y="141" dy="0" style="display:none"></text>')
    body += pill(cell_x(0) + BW / 2, 204, "begin", W, 60); body.append(arrow(cell_x(0) + BW / 2, 202, 178, mid))
    body += pill(cell_x(15) + BW / 2, 204, "end", W, 48); body.append(arrow(cell_x(15) + BW / 2, 202, 178, mid))
    body.append('<text class="fg-note fg-note--r" x="%d" y="221">Past-the-last element</text>' % (cell_x(15) + BW / 2 - 40))
    write("range-rbegin-rend.svg", W, H, "nj-fig--range", "fig-rbe-title",
          "Two rows of sixteen cells. The upper row shows the reversed sequence: rend() points to a dashed position before the first element and rbegin() to the last element. The lower row shows the forward sequence: begin() points to the first element and end() to a dashed position after the last element. A reverse iterator stores an iterator to the next element, so rend() corresponds to begin() and rbegin() to end().", body, defs)

callback(); ranges1(); ranges2()
