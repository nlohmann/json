"""Draws the json_view illustrations of docs/features/json_view.md as inline SVGs into docs/images/.

The SVGs are not images: the page includes their text with `--8<-- "images/json_view_layout.svg"` (and
json_view_lifetime.svg, json_view_edit_0.svg ... json_view_edit_4.svg), so they pick up the colours and fonts of
the page (see the `nj-fig` rules in docs/css/brand.css and the `nj-jsonview-*` rules in docs/css/fig-jsonview.css).
The edit frames are the steps of a stepper (docs/js/fig-jsonview.js); without JavaScript they show one below the
other. Run `python3 scripts/figures/json_view_layout.py` from docs/mkdocs after changing the drawing, and commit the
generated files. In SVG text write the word JSON as `J&#8203;SON`, otherwise the abbreviation extension wraps it in
an <abbr> and the text disappears.

The node fields drawn here follow `struct node` in include/nlohmann/detail/view/node.hpp and the edit storage in
detail/view/edit.hpp and edit_storage.hpp, for the 54-byte text in TEXT (9 nodes).
"""
import html
from pathlib import Path

OUT = Path(__file__).resolve().parents[2] / "docs" / "images"
TEXT = '{"port": 6379, "price": 19.90, "tags": ["eu", "a\\"b"]}'
assert len(TEXT) == 54

# concept -> colour class (fig-jsonview.css maps them to brand colours)
STRUCT, KEY, STR, NUM, DEC, OWN, BAD, LINE = "struct", "key", "str", "num", "dec", "own", "bad", "line"


def esc(s):
    return html.escape(s, quote=True)


def write(name, W, H, tid, title, desc, body, extra_cls=""):
    s = ['<svg class="nj-fig nj-jsonview %s" viewBox="0 0 %d %d" role="img" aria-labelledby="%s %s-d" '
         'xmlns="http://www.w3.org/2000/svg">' % (extra_cls, W, H, tid, tid),
         '<title id="%s">%s</title>' % (tid, esc(title).replace("\u200b", "&#8203;")),
         '<desc id="%s-d">%s</desc>' % (tid, esc(desc))]
    s += body
    s.append('</svg>')
    text = "\n".join(s) + "\n"
    assert "\n\n" not in text  # a blank line would end the raw HTML block
    (OUT / name).write_text(text)


def markers(prefix, kinds=(LINE, STR, KEY, NUM, DEC, OWN, STRUCT, BAD)):
    """one arrow head per colour; ids are unique per SVG (hidden frames must not own the markers)"""
    m = ['<defs>']
    for k in kinds:
        m.append('<marker id="%s-%s" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" '
                 'orient="auto-start-reverse"><path class="nj-jsonview-c-%s nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>' % (prefix, k, k))
    m.append('</defs>')
    return m


def rect(x, y, w, h, cls, c=None, rx=5):
    cc = " nj-jsonview-c-%s" % c if c else ""
    return '<rect class="%s%s" x="%g" y="%g" width="%g" height="%g" rx="%g"/>' % (cls, cc, x, y, w, h, rx)


def text(x, y, s, cls="nj-jsonview-t", c=None, anchor=None):
    cc = " nj-jsonview-c-%s" % c if c else ""
    a = ' text-anchor="%s"' % anchor if anchor else ""
    return '<text class="%s%s" x="%g" y="%g"%s xml:space="preserve">%s</text>' % (cls, cc, x, y, a, esc(s))


def curve(x1, y1, x2, y2, c, prefix, dashed=False, bend=None, head=True):
    """vertical-ish cubic from (x1, y1) to (x2, y2)"""
    b = bend if bend is not None else (y2 - y1) / 2
    d = "M%g %g C%g %g %g %g %g %g" % (x1, y1, x1, y1 + b, x2, y2 - b, x2, y2)
    return '<path class="nj-jsonview-arr nj-jsonview-c-%s%s" d="%s"%s/>' % (
        c, " nj-jsonview-dash" if dashed else "", d, ' marker-end="url(#%s-%s)"' % (prefix, c) if head else "")


def line(x1, y1, x2, y2, c, prefix, dashed=False, head=True):
    return '<path class="nj-jsonview-arr nj-jsonview-c-%s%s" d="M%g %g L%g %g"%s/>' % (
        c, " nj-jsonview-dash" if dashed else "", x1, y1, x2, y2, ' marker-end="url(#%s-%s)"' % (prefix, c) if head else "")


# ---------------------------------------------------------------- the parsed index of TEXT
# (index, colour, kind, field lines, source span or None, label for compact frames)
NODES = [
    (0, STRUCT, "object", ["len 3", "next 9"], None, "{ } 3"),
    (1, KEY, "key", ["off 2", "len 4"], (2, 6), '"port"'),
    (2, NUM, "uint", ["6379", "(converted)"], (9, 13), "6379"),
    (3, KEY, "key", ["off 16", "len 5"], (16, 21), '"price"'),
    (4, NUM, "float", ["off 24", "len 5"], (24, 29), "19.90"),
    (5, KEY, "key", ["off 32", "len 4"], (32, 36), '"tags"'),
    (6, STRUCT, "array", ["len 2", "next 3"], None, "[ ] 2"),
    (7, STR, "string", ["off 41", "len 2"], (41, 43), '"eu"'),
    (8, DEC, "string", ["escaped", "len 3"], (47, 51), 'a"b'),
]


def ribbon(body, x0, y, cw, prefix, label=True):
    """the source text as a strip of bytes, with the spans the nodes refer to tinted"""
    w = cw * len(TEXT)
    body.append(rect(x0, y, w, 26, "nj-jsonview-ribbon", rx=4))
    for _, c, kind, _, span, _ in NODES:
        if span:
            body.append(rect(x0 + span[0] * cw + 1, y + 2, (span[1] - span[0]) * cw - 2, 22, "nj-jsonview-span", c, rx=3))
    for i, ch in enumerate(TEXT):
        if ch != " ":
            body.append(text(x0 + i * cw + cw / 2, y + 17.5, ch, "nj-jsonview-mono nj-jsonview-byte", anchor="middle"))
    if label:
        for off in (0, 10, 20, 30, 40, 50):
            body.append(text(x0 + off * cw + cw / 2, y + 40, str(off), "nj-jsonview-tiny", anchor="middle"))
    return w


# ---------------------------------------------------------------- figure 1: parse() vs json_document
def layout():
    W, H, P = 840, 692, "jvl"
    b = markers(P)
    # --- panel A: basic_json::parse()
    b.append(text(16, 26, "basic_json::parse(): a tree, every array, object, and string in its own heap allocation", "nj-jsonview-h"))
    b.append(rect(16, 98, 60, 34, "nj-jsonview-box"))
    b.append(text(46, 120, "json", "nj-jsonview-mono", anchor="middle"))
    b.append(line(76, 115, 106, 115, LINE, P))
    b.append(rect(108, 98, 84, 34, "nj-jsonview-heap"))
    b.append(text(150, 120, "std::map", "nj-jsonview-mono", anchor="middle"))
    rows = [('"port"', "6379", None), ('"price"', "19.9", "double: 19.90 is gone"), ('"tags"', "\u2022", None)]
    for i, (k, v, note) in enumerate(rows):
        y = 50 + i * 48
        b.append(curve(192, 115, 226, y + 17, LINE, P, bend=0))
        b.append(rect(228, y, 180, 34, "nj-jsonview-heap"))
        b.append(text(240, y + 22, k, "nj-jsonview-mono", KEY))
        b.append(text(396, y + 22, v, "nj-jsonview-mono", NUM if i < 2 else LINE, anchor="end"))
        if note:
            b.append(text(418, y + 22, note, "nj-jsonview-note"))
    yt = 50 + 2 * 48 + 17
    b.append(line(408, yt, 442, yt, LINE, P))
    b.append(rect(444, yt - 17, 104, 34, "nj-jsonview-heap"))
    b.append(text(496, yt + 5, "std::vector", "nj-jsonview-mono", anchor="middle"))
    b.append(line(548, yt, 576, yt, LINE, P))
    b.append(rect(578, yt - 17, 92, 34, "nj-jsonview-heap"))
    b.append('<path class="nj-jsonview-sep" d="M624 %g V%g"/>' % (yt - 17, yt + 17))
    b.append(text(601, yt + 5, "json", "nj-jsonview-mono", anchor="middle"))
    b.append(text(647, yt + 5, "json", "nj-jsonview-mono", anchor="middle"))
    b.append(curve(601, yt - 17, 706, 130, LINE, P, bend=-20))
    b.append(curve(647, yt + 17, 706, 196, LINE, P, bend=20))
    b.append(rect(708, 113, 126, 34, "nj-jsonview-heap"))
    b.append(text(771, 135, "std::string eu", "nj-jsonview-mono nj-jsonview-sm", STR, anchor="middle"))
    b.append(rect(708, 179, 126, 34, "nj-jsonview-heap"))
    b.append(text(771, 201, 'std::string a"b', "nj-jsonview-mono nj-jsonview-sm", STR, anchor="middle"))
    # legend
    b.append(rect(16, 186, 18, 14, "nj-jsonview-heap", rx=3))
    b.append(text(42, 198, "a separate heap allocation", "nj-jsonview-note"))
    # --- panel B: json_document::parse()
    y0 = 252
    b.append('<path class="nj-jsonview-sep" d="M16 %g H824"/>' % (y0 - 18))
    b.append(text(16, y0 + 10, "json_document::parse(): the source text stays where it is; one flat index of 16-byte nodes", "nj-jsonview-h"))
    b.append(text(16, y0 + 38, "source text, 54 bytes (borrowed, or owned by the document)", "nj-jsonview-note"))
    cw, rx0, ry = 14, 42, y0 + 48
    ribbon(b, rx0, ry, cw, P)
    # node strip inside the document frame
    fy = ry + 66
    b.append(rect(16, fy, 808, 254, "nj-jsonview-frame", rx=10))
    nw, gap, nx0, ny, nh = 84, 4, 36, fy + 40, 68
    b.append(text(30, fy + 236, "json_document: owns the node index and the buffer of decoded strings", "nj-jsonview-note nj-jsonview-strong"))
    b.append(text(30, ny + nh + 26, "node index: 9 nodes \u00d7 16 bytes = 144 bytes, in document order", "nj-jsonview-note"))
    for i, c, kind, fields, span, _ in NODES:
        x = nx0 + i * (nw + gap)
        b.append(rect(x, ny, nw, nh, "nj-jsonview-node", c))
        b.append(text(x + 6, ny + 14, str(i), "nj-jsonview-tiny"))
        b.append(text(x + nw / 2, ny + 28, kind, "nj-jsonview-kind", c, anchor="middle"))
        for j, f in enumerate(fields):
            b.append(text(x + nw / 2, ny + 45 + j * 14, f, "nj-jsonview-mono nj-jsonview-xs", anchor="middle"))
        if span and c in (KEY, STR, NUM) and not (c == NUM and kind == "uint"):
            sx = rx0 + (span[0] + span[1]) / 2 * cw
            b.append(curve(x + nw / 2, ny, sx, ry + 28, c, P))
    # the integer has no pointer: its value is in the node
    # decoded strings
    dx, dy = 740, ny + nh + 44
    n8x = nx0 + 8 * (nw + gap) + nw / 2
    b.append(text(dx + 33, dy + 50, "decoded strings", "nj-jsonview-note", anchor="middle"))
    b.append(rect(dx, dy, 3 * 22, 30, "nj-jsonview-node", DEC, rx=4))
    for k, ch in enumerate('a"b'):
        b.append(text(dx + 11 + k * 22, dy + 20, ch, "nj-jsonview-mono", anchor="middle"))
    b.append(curve(n8x, ny + nh, dx + 33, dy, DEC, P))
    # the view: two pointers
    vx, vy = 480, fy + 254 + 28
    b.append(text(vx - 10, vy + 22, 'json_view v = doc.root()["tags"]', "nj-jsonview-mono nj-jsonview-sm", anchor="end"))
    b.append(rect(vx, vy, 140, 34, "nj-jsonview-node", STRUCT, rx=6))
    b.append('<path class="nj-jsonview-sep" d="M%g %g V%g"/>' % (vx + 70, vy, vy + 34))
    b.append(text(vx + 35, vy + 22, "doc*", "nj-jsonview-mono", anchor="middle"))
    b.append(text(vx + 105, vy + 22, "node*", "nj-jsonview-mono", anchor="middle"))
    b.append(line(vx + 35, vy, vx + 35, fy + 254 + 2, STRUCT, P))
    n6x = nx0 + 6 * (nw + gap) + nw / 2
    b.append(curve(vx + 105, vy, n6x, ny + nh, STRUCT, P))
    b.append(text(30, ny + nh + 50, "integers are converted while parsing and kept in their node;", "nj-jsonview-note"))
    b.append(text(30, ny + nh + 68, "floats and strings point back into the text", "nj-jsonview-note"))
    write("json_view_layout.svg", W, H, "fig-jvl-title",
          "The same J\u200bSON text parsed by basic_json::parse() and by json_document::parse()",
          "The text {\"port\": 6379, \"price\": 19.90, \"tags\": [\"eu\", \"a\\\"b\"]}. Top: basic_json::parse() builds a tree: "
          "the root json value points to a std::map whose three nodes are separate heap allocations; the price is stored "
          "as the double 19.9; the tags array is a std::vector of two json values, each pointing to its own std::string. "
          "Bottom: json_document::parse() keeps the 54 bytes of source text and builds a flat index of nine 16-byte nodes in "
          "document order: object, key port, unsigned integer 6379 (the converted value is in the node), key price, float, "
          "key tags, array, string eu, and an escaped string. Keys, the float, and the plain string point back into the "
          "source text; the escaped string points into the document's buffer of decoded strings. A json_view is two "
          "pointers: one to the document and one to a node, here the array.", b)


# ---------------------------------------------------------------- figure 2: lifetimes
def lifetime():
    W, P = 840, "jvt"
    L, R = 210, 820
    b = markers(P, (BAD,))
    b.append(rect(L, 12, 34, 12, "nj-jsonview-bar", STRUCT, rx=3))
    b.append(text(L + 42, 23, "alive / valid", "nj-jsonview-note"))
    b.append(rect(L + 160, 12, 34, 12, "nj-jsonview-bad", rx=3))
    b.append(text(L + 202, 23, "dangling: using it is undefined behavior", "nj-jsonview-note"))
    b.append(line(L, 44, R, 44, LINE, P, head=False))
    b.append(text(R, 38, "time \u2192", "nj-jsonview-tiny", anchor="end"))
    scen = [
        ("The borrowed text is destroyed", 470, "text destroyed", [
            ("std::string text", [(L, 470, "ok"), ], "end"),
            ("json_document doc", [(L + 60, 470, "ok"), (470, R, "bad")], None),
            ("json_view v", [(L + 120, 470, "ok"), (470, R, "bad")], None)]),
        ("The document is re-parsed", 470, "doc.read(other)", [
            ("json_document doc", [(L, R, "ok")], None),
            ("json_view v", [(L + 60, 470, "ok"), (470, R, "bad")], None),
            ("v = doc.root()", [(530, R, "ok")], None)]),
        ("The document is shrunk", 470, "doc.shrink_to_fit()", [
            ("json_document doc", [(L, R, "ok")], None),
            ("json_view v", [(L + 60, 470, "ok"), (470, R, "bad")], None),
            ("v = doc.root()", [(530, R, "ok")], None)]),
        ("The document is moved, then destroyed", 680, "moved is destroyed", [
            ("json_document doc", [(L, 420, "ok")], None),
            ("moved = std::move(doc)", [(420, 680, "ok")], "end"),
            ("json_view v", [(L + 60, 680, "ok"), (680, R, "bad")], None)]),
    ]
    y = 70
    for title, ev, evlabel, rows in scen:
        b.append(text(16, y + 4, title, "nj-jsonview-h nj-jsonview-sm2"))
        top = y + 14
        for k, (name, segs, end) in enumerate(rows):
            ry = top + k * 28
            b.append(text(L - 12, ry + 15, name, "nj-jsonview-mono nj-jsonview-sm", anchor="end"))
            for x1, x2, st in segs:
                b.append(rect(x1, ry + 3, x2 - x1, 16, "nj-jsonview-bar" if st == "ok" else "nj-jsonview-bad", STRUCT if st == "ok" else None, rx=3))
        bottom = top + len(rows) * 28
        if title.startswith("The document is moved"):
            b.append('<path class="nj-jsonview-evt nj-jsonview-evt--ok" d="M420 %g V%g"/>' % (top - 2, bottom))
            b.append(text(424, top - 4, "std::move: views stay valid", "nj-jsonview-tiny"))
        b.append('<path class="nj-jsonview-evt" d="M%g %g V%g"/>' % (ev, top - 2, bottom))
        b.append(text(ev + 4, top - 4, evlabel, "nj-jsonview-tiny nj-jsonview-c-bad"))
        if title == "The borrowed text is destroyed":
            b.append(text(476, top + 2 * 28 + 15, "every view, and the document itself", "nj-jsonview-note nj-jsonview-onbad"))
        elif title.startswith("The document is moved"):
            pass
        else:
            b.append(text(476, top + 28 + 15, "views taken before", "nj-jsonview-note nj-jsonview-onbad"))
            b.append(text(536, top + 2 * 28 + 15, "a fresh view is valid again", "nj-jsonview-note nj-jsonview-onok"))
        y = bottom + 30
    H = y - 10
    write("json_view_lifetime.svg", W, H, "fig-jvt-title",
          "When a json_view becomes invalid",
          "Four timelines. First: a document borrows a std::string; when the string is destroyed, the document and every view "
          "taken from it dangle. Second: doc.read() re-parses the document; views taken before are invalid, a fresh view from "
          "root() is valid. Third: doc.shrink_to_fit() has the same effect. Fourth: moving the document does not invalidate its "
          "views; destroying the moved-to document does.", b)


# ---------------------------------------------------------------- figure 3: edit frames
NW, NG, NX0 = 84, 4, 36   # parsed nodes
OW, OG, OX0 = 54, 3, 16   # owned storage slots


def nx(i):
    return NX0 + i * (NW + NG)


def ox(i):
    return OX0 + i * (OW + OG)


# owned storage in allocation order (all in the first 64-node chunk), per step
# entries: (colour, line1, line2, link target) ; link target = ("p", i) parsed node or ("o", j) owned slot
OWN_STEPS = {
    2: [(STRUCT, "header", "[ ] 1", None), (OWN, "link", "\u2192 8", ("p", 8)), (None, "", "", None)],
}
OWN_STEPS[3] = [(STRUCT, "header", "[ ] 2", None), (OWN, "link", "\u2192 8", ("p", 8)), (OWN, "link", "\u2192 3'", ("o", 3)),
                (STR, "string", '"new"', None)]
OWN_STEPS[4] = OWN_STEPS[3] + [(NUM, "uint", "3", None), (STRUCT, "header", "{ } 4", None),
                               (KEY, "key", "port", None), (OWN, "link", "\u2192 2", ("p", 2)),
                               (KEY, "key", "price", None), (OWN, "link", "\u2192 4", ("p", 4)),
                               (KEY, "key", "tags", None), (OWN, "link", "\u2192 6", ("p", 6)),
                               (KEY, "key", "retries", None), (OWN, "link", "\u2192 4'", ("o", 4))]

STEPS = [
    ("parsed", "After parse: nine nodes, nothing owned yet"),
    ('doc.set(doc.root(), "port", 6380)', "set: the node of the integer is overwritten in place"),
    ('doc.erase(doc.root()["tags"], 0)', "erase: the array moves to a block of links in owned storage"),
    ('doc.push_back(doc.root()["tags"], "new")', "push_back: a new node, and a link appended to the block"),
    ('doc.set(doc.root(), "retries", 3)', "set of a new member: the object moves to a block as well"),
]

DUMPS = [
    '{"port":6379,"price":19.90,"tags":["eu","a\\"b"]}',
    '{"port":6380,"price":19.90,"tags":["eu","a\\"b"]}',
    '{"port":6380,"price":19.90,"tags":["a\\"b"]}',
    '{"port":6380,"price":19.90,"tags":["a\\"b","new"]}',
    '{"port":6380,"price":19.90,"tags":["a\\"b","new"],"retries":3}',
]


def edit_frame(step):
    W, H, P = 840, 372, "jve%d" % step
    b = markers(P, (LINE, OWN, STRUCT, BAD))
    b.append(text(16, 22, "parsed index: fixed, never moves", "nj-jsonview-note nj-jsonview-strong"))
    b.append(text(824, 22, "the source text is never written", "nj-jsonview-note", anchor="end"))
    ny, nh = 34, 50
    moved = {6: 0} if step >= 2 else {}
    if step >= 4:
        moved[0] = 5
    for i, c, kind, fields, span, short in NODES:
        x = nx(i)
        cls = "nj-jsonview-node"
        label = short
        changed = False
        if i == 2 and step >= 1:
            label, changed = "6380", step == 1
        if c == KEY:
            label = label.strip('"')
        gap_node = (i == 7 and step >= 2)
        if gap_node:
            cls += " nj-jsonview-gap"
        if changed:
            cls += " nj-jsonview-hot"
        b.append(rect(x, ny, NW, nh, cls, c))
        b.append(text(x + 6, ny + 13, str(i), "nj-jsonview-tiny"))
        b.append(text(x + NW / 2, ny + 27, kind, "nj-jsonview-kind nj-jsonview-xs", c, anchor="middle"))
        if i in moved:
            b.append(text(x + NW - 5, ny + 13, "moved", "nj-jsonview-tiny nj-jsonview-c-struct nj-jsonview-strong", anchor="end"))
        b.append(text(x + NW / 2, ny + 43, label, "nj-jsonview-mono nj-jsonview-sm", anchor="middle"))
        if gap_node:
            b.append(text(x + NW / 2, ny + nh + 14, "unreferenced", "nj-jsonview-tiny nj-jsonview-c-bad", anchor="middle"))
    # owned storage
    oy, oh = 196, 46
    b.append(text(16, oy + oh + 46, "owned storage: allocated on demand, never moves", "nj-jsonview-note nj-jsonview-strong", OWN))
    slots = OWN_STEPS.get(step, [])
    b.append(rect(OX0 - 6, oy - 4, 820, oh + 8, "nj-jsonview-store", rx=8))
    if not slots:
        b.append(text(OX0 + 10, oy + 28, "empty: a read-only json_document has none of this", "nj-jsonview-note"))
    for j, (c, l1, l2, tgt) in enumerate(slots):
        x = ox(j)
        if c is None:
            b.append(rect(x, oy, OW, oh, "nj-jsonview-node nj-jsonview-free", OWN))
            b.append(text(x + OW / 2, oy + 28, "free", "nj-jsonview-tiny", anchor="middle"))
            continue
        hot = (step == 2 and j < 3) or (step == 3 and j in (2, 3)) or (step == 4 and j >= 4)
        b.append(rect(x, oy, OW, oh, "nj-jsonview-node" + (" nj-jsonview-hot" if hot else ""), c))
        b.append(text(x + OW - 4, oy + 11, "%d'" % j, "nj-jsonview-tiny", anchor="end"))
        b.append(text(x + OW / 2, oy + 24, l1, "nj-jsonview-kind nj-jsonview-xs", c, anchor="middle"))
        b.append(text(x + OW / 2, oy + 39, l2, "nj-jsonview-mono nj-jsonview-xs", anchor="middle"))
        if tgt:
            cx = x + OW / 2
            if tgt[0] == "p":
                b.append(curve(cx, oy, nx(tgt[1]) + NW / 2 + (8 if tgt[1] in moved else 0), ny + nh, OWN, P))
            else:
                tx = ox(tgt[1]) + OW / 2
                d = "M%g %g C%g %g %g %g %g %g" % (cx, oy + oh, cx, oy + oh + 26, tx, oy + oh + 26, tx, oy + oh + 2)
                b.append('<path class="nj-jsonview-arr nj-jsonview-c-own" d="%s" marker-end="url(#%s-own)"/>' % (d, P))
    # moved containers point to their block header
    for i, hj in moved.items():
        b.append(curve(nx(i) + NW / 2 - 8, ny + nh, ox(hj) + OW / 2, oy, STRUCT, P, dashed=True))
    # edit text buffer
    texts = ["new", "retries"][: (1 if step == 3 else 2 if step >= 4 else 0)]
    if texts:
        tx0 = 596
        b.append(text(tx0 - 8, oy + oh + 40, "edited text", "nj-jsonview-note", anchor="end"))
        b.append(rect(tx0, oy + oh + 22, 10 * len("".join(texts)) + 12, 26, "nj-jsonview-node", STR, rx=4))
        b.append(text(tx0 + 6, oy + oh + 40, "".join(texts), "nj-jsonview-mono nj-jsonview-sm"))
    # views and iterators
    vy = 318
    b.append('<path class="nj-jsonview-sep" d="M16 %g H824"/>' % (vy - 18))
    b.append(text(16, vy, 'view v = root()["tags"] (taken after parse):', "nj-jsonview-mono nj-jsonview-xs"))
    b.append(text(320, vy, "valid, sees every edit", "nj-jsonview-note nj-jsonview-c-struct nj-jsonview-strong"))
    b.append(text(16, vy + 20, "iterator over tags (taken after parse):", "nj-jsonview-mono nj-jsonview-xs"))
    if step >= 2:
        b.append(text(320, vy + 20, "invalid: tags no longer uses the parsed layout", "nj-jsonview-note nj-jsonview-c-bad nj-jsonview-strong"))
    else:
        b.append(text(320, vy + 20, "valid", "nj-jsonview-note nj-jsonview-c-struct nj-jsonview-strong"))
    b.append(text(16, vy + 42, "dump(): " + DUMPS[step], "nj-jsonview-mono nj-jsonview-xs nj-jsonview-muted"))
    code, cap = STEPS[step]
    write("json_view_edit_%d.svg" % step, W, H, "fig-jve%d-title" % step,
          "Step %d of %d: %s" % (step + 1, len(STEPS), code),
          cap + ". The dump with number_format::source is " + DUMPS[step] + ".", b, "nj-jsonview-editfig")


layout()
lifetime()
for s in range(len(STEPS)):
    edit_frame(s)
