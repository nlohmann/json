"""Draws the exception id map of home/exceptions.md as an inline SVG into docs/images/exception_map.svg.

The SVG is not an image: the page includes its text with `--8<-- "images/exception_map.svg"`, so it picks up the
colours and fonts of the page (see the `nj-fig` rules in docs/css/brand.css and the `nj-exceptions-*` rules in
docs/css/fig-exceptions.css). The file holds two drawings of the same map, a wide one and a narrow one for phones;
the CSS shows one of them. Every id chip is a link to the `###` section of that id on the page, every family box a
link to the family's `##` section.

Run `python3 scripts/figures/exception_map.py` from docs/mkdocs after changing the drawing or after adding an
exception section to home/exceptions.md (the ids are read from the page), and commit the generated file. In SVG text
write the word JSON as `J&#8203;SON`, otherwise the abbreviation extension wraps it in an <abbr> and the text
disappears.
"""
import html
import re
from pathlib import Path

OUT = Path(__file__).resolve().parents[2] / "docs" / "images"
PAGE = Path(__file__).resolve().parents[2] / "docs" / "home" / "exceptions.md"
P = "nj-exceptions-"

# family name, id range label, anchor of the family section, extra member
FAMILIES = [
    ("parse_error", "1xx", "parse-errors", "byte"),
    ("invalid_iterator", "2xx", "iterator-errors", None),
    ("type_error", "3xx", "type-errors", None),
    ("out_of_range", "4xx", "out-of-range", None),
    ("other_error", "5xx", "further-exceptions", None),
]

# the chips show the id only; naming just some of them was confusing
LABELS = {}


GLOSSARY = Path(__file__).resolve().parents[2] / "includes" / "glossary.md"
ABBRS = sorted(re.findall(r"^\*\[([^\]]+)\]:", GLOSSARY.read_text(), re.M), key=len, reverse=True)


def noabbr(s):
    """Breaks every glossary abbreviation with a zero-width space, so the abbr extension leaves SVG text alone."""
    for a in ABBRS:
        s = re.sub(r"(?<![\w&#])%s(?!\w)" % re.escape(a), a[0] + "&#8203;" + a[1:], s)
    return s


def ids_on_page():
    found = {}
    for m in re.finditer(r"^### json\.exception\.(\w+)\.(\d+)\s*$", PAGE.read_text(), re.M):
        found.setdefault(m.group(1), []).append(int(m.group(2)))
    return found


def text_w(s, size):
    """Rough advance width of Inter at the given size (good enough to size chips)."""
    w = 0.0
    for c in s:
        if c in "il.,:;'|![]()":
            w += 0.28
        elif c in " ft":
            w += 0.32
        elif c in "mwMW":
            w += 0.85
        elif c.isupper() or c.isdigit():
            w += 0.64
        else:
            w += 0.55
    return w * size


def esc(s):
    return html.escape(s, quote=True).replace("[", "&#91;").replace("]", "&#93;")


MONO = 7.9    # JetBrains Mono advance at 13px
CH = 28       # chip height
GAP = 6


def chip(x, y, fam, num):
    label = LABELS.get(num)
    w = 3 * MONO + 18 + (text_w(label, 12.5) + 10 if label else 0)
    anchor = "jsonexception%s%d" % (fam, num)
    aria = "json.exception.%s.%d%s" % (fam, num, (": " + label) if label else "")
    s = ['<a class="%schip%s" xlink:href="#%s" aria-label="%s">' % (P, " %schip--named" % P if label else "", anchor, esc(aria)),
         '<rect x="%g" y="%g" width="%g" height="%d" rx="6"/>' % (x, y, w, CH),
         '<text class="%sid" x="%g" y="%g">%d</text>' % (P, x + 9, y + CH / 2 + 4.5, num)]
    if label:
        s.append('<text class="%slabel" x="%g" y="%g">%s</text>' % (P, x + 9 + 3 * MONO + 9, y + CH / 2 + 4.5, noabbr(esc(label))))
    s.append('</a>')
    return w, "".join(s)


def flow(fam, nums, x0, x1, y0):
    """Places the chips of one family left to right, wrapping at x1. Returns (svg parts, bottom y)."""
    parts, x, y = [], x0, y0
    for n in nums:
        w, _ = chip(0, 0, fam, n)
        if x > x0 and x + w > x1:
            x, y = x0, y + CH + GAP
        _, s = chip(x, y, fam, n)
        parts.append(s)
        x += w + GAP
    return parts, y + CH


def box(x, y, w, h, title, sub, href=None, cls=""):
    s = []
    if href:
        s.append('<a class="%sfam" xlink:href="#%s" aria-label="%s">' % (P, href, esc(title + ", " + sub)))
    s.append('<rect class="%sbox%s" x="%g" y="%g" width="%g" height="%g" rx="7"/>' % (P, cls, x, y, w, h))
    s.append('<text class="%sname" x="%g" y="%g">%s</text>' % (P, x + 12, y + 22, noabbr(esc(title))))
    s.append('<text class="%ssub" x="%g" y="%g">%s</text>' % (P, x + 12, y + 41, noabbr(esc(sub))))
    if href:
        s.append('</a>')
    return "".join(s)


def drawing(W, narrow, suffix):
    global CH
    CH = 34 if narrow else 28   # larger touch targets on phones
    ids = ids_on_page()
    mid = "nj-exc-tri-" + suffix
    body = []
    trunk = 34
    # std::exception and json::exception
    body.append(box(12, 12, 190 if narrow else 200, 52, "std::exception", "C++ standard library base"))
    body.append('<line class="%sedge" x1="%d" y1="%d" x2="%d" y2="%d" marker-end="url(#%s)"/>' % (P, trunk, 104, trunk, 66, mid))
    body.append(box(12, 104, 250 if narrow else 300, 52, "json::exception", "id, what() \u00b7 catch-all"))
    y = 196
    last_branch = y
    fam_w = W - 64 - 12 if narrow else 214
    for fam, rng, href, member in FAMILIES:
        nums = ids[fam]
        sub = "%s \u00b7 %d ids" % (rng, len(nums)) + (" \u00b7 adds member %s" % member if member else "")
        body.append('<line class="%sedge" x1="%d" y1="%d" x2="%d" y2="%d"/>' % (P, trunk, y + 26, 64, y + 26))
        last_branch = y + 26
        body.append(box(64, y, fam_w, 52, "json::" + fam, sub, href, " %sbox--fam" % P))
        if narrow:
            parts, bottom = flow(fam, nums, 64, W - 12, y + 52 + 10)
        else:
            parts, bottom = flow(fam, nums, 64 + fam_w + 16, W - 12, y + 12)
        body += parts
        y = max(bottom, y + 52) + 26
    # trunk from json::exception down to the last family, with the inheritance triangle at the top
    body.insert(0, '<line class="%sedge" x1="%d" y1="%d" x2="%d" y2="%d" marker-end="url(#%s)"/>' % (P, trunk, last_branch, trunk, 158, mid))
    H = y - 14
    defs = ('<defs><marker id="%s" viewBox="0 0 12 12" refX="11" refY="6" markerWidth="11" markerHeight="11" orient="auto">'
            '<path class="%stri" d="M1 1 L11 6 L1 11 z"/></marker></defs>' % (mid, P))
    tid, did = "nj-exc-map-title-" + suffix, "nj-exc-map-desc-" + suffix
    total = sum(len(v) for v in ids.values())
    desc = ("Class tree: std::exception is the base of json::exception, which is the base of the five exception "
            "families parse_error (ids 1xx), invalid_iterator (2xx), type_error (3xx), out_of_range (4xx) and "
            "other_error (5xx). Each family lists the ids documented on this page, %d in total; every id links to "
            "its section." % total)
    s = ['<svg class="nj-fig %smap %smap--%s" viewBox="0 0 %d %d" aria-labelledby="%s %s" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'
         % (P, P, "narrow" if narrow else "wide", W, H, tid, did),
         '<title id="%s">Exception id map</title>' % tid,
         '<desc id="%s">%s</desc>' % (did, noabbr(esc(desc))),
         defs] + body + ['</svg>']
    return "\n".join(s)


def main():
    out = drawing(760, False, "w") + "\n" + drawing(360, True, "n") + "\n"
    (OUT / "exception_map.svg").write_text(out)


main()
