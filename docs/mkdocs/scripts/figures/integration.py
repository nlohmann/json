"""Draws the 3.x / 4.0 lane diagram of community/roadmap.md as an inline SVG into docs/images/.

The rows come from the page itself: the macro table under "Trying out 4.0 today" gives each macro, its 3.x default,
whether 4.0 removes it, and the version that added it; the `#define` block below that table gives the 4.0 value. Run
`python3 scripts/figures/integration.py` from docs/mkdocs after changing that section, and commit the generated
docs/images/roadmap_lanes.svg. The page includes the SVG text with `--8<-- "images/roadmap_lanes.svg"`, so it follows
the light/dark toggle (see the `nj-fig` rules in docs/css/brand.css and the `nj-int-*` rules in
docs/css/fig-integration.css). In SVG text write J&#8203;SON and A&#8203;PI, otherwise the abbreviation extension
wraps the word in an <abbr> and the text disappears.
"""
import re
import sys
from pathlib import Path

DOCS = Path(__file__).resolve().parents[2] / "docs"
OUT = Path(__file__).resolve().parents[2] / "docs" / "images"
PAGE = DOCS / "community" / "roadmap.md"


def esc(text):
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def vkey(version):
    return tuple(int(p) for p in version.split("."))


def parse(markdown):
    section = markdown.split("### Trying out 4.0 today", 1)[1].split("\n### ", 1)[0]
    rows = []
    for line in section.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        m = re.match(r"\[`(JSON_[A-Z0-9_]+)`\]", cells[0]) if len(cells) == 5 else None
        if not m:
            continue
        default = re.fullmatch(r"`(\d)`", cells[1])
        added = re.fullmatch(r"(\d+\.\d+\.\d+)", cells[4])
        if not default or not added:
            sys.exit("cannot parse row: " + line)
        rows.append({"macro": m.group(1), "default": default.group(1), "added": added.group(1),
                     "removed": cells[2].startswith("removed")})
    values = dict(re.findall(r"^#define (JSON_[A-Z0-9_]+) (\d)$", section, re.MULTILINE))
    for row in rows:
        if row["macro"] not in values:
            sys.exit("no #define for " + row["macro"])
        row["v4"] = values[row["macro"]]
    if not rows:
        sys.exit("no macro rows found in " + str(PAGE))
    return rows


def draw(rows):
    W, ROW, TOP = 880, 34, 168
    H = TOP + ROW * len(rows) + 30
    versions = sorted({r["added"] for r in rows}, key=vkey)
    s = ['<svg class="nj-fig nj-fig--lanes" viewBox="0 0 %d %d" role="img" aria-labelledby="nj-int-lanes-title" '
         'xmlns="http://www.w3.org/2000/svg">' % (W, H)]
    s.append('<title id="nj-int-lanes-title">Two lanes: the 3.x release train, whose minor and patch releases do not '
             'break code that uses the public A&#8203;PI, followed by version 4.0, which has no release date yet. '
             'Each breaking change is a macro that is available in 3.x today with its 3.x default and becomes the '
             'default in 4.0: %s.</title>'
             % "; ".join("%s, added in %s, 3.x default %s, 4.0 value %s%s"
                         % (r["macro"], r["added"], r["default"], r["v4"], ", macro removed" if r["removed"] else "")
                         for r in rows))
    s.append('<defs><marker id="nj-int-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
             'orient="auto"><path class="fg-head" d="M0 1 L10 5 L0 9 z"/></marker></defs>')
    # lanes
    s.append('<rect class="nj-int-lane" x="16" y="16" width="600" height="56" rx="10"/>')
    s.append('<text class="nj-int-lanetext" x="32" y="41">3.x release train</text>')
    s.append('<text class="nj-int-mute" x="32" y="60">available today</text>')
    x0, x1 = 300, 590
    step = (x1 - x0) / max(1, len(versions) - 1) if len(versions) > 1 else 0
    for i, v in enumerate(versions):
        x = x0 + i * step if len(versions) > 1 else (x0 + x1) / 2
        s.append('<line class="nj-int-axis" x1="%g" y1="30" x2="%g" y2="44"/>' % (x, x))
        s.append('<text class="nj-int-mute" x="%g" y="60" text-anchor="middle">%s</text>' % (x, v))
    s.append('<line class="fg-arrow" x1="210" y1="37" x2="600" y2="37"/>')
    s.append('<line class="fg-arrow fg-arrow--dash" x1="618" y1="44" x2="660" y2="44" marker-end="url(#nj-int-arrow)"/>')
    s.append('<rect class="nj-int-lane nj-int-lane--future" x="664" y="16" width="200" height="56" rx="10"/>')
    s.append('<text class="nj-int-lanetext" x="680" y="41">4.0</text>')
    s.append('<text class="nj-int-mute" x="680" y="60">no release date yet</text>')
    # guarantee
    s.append('<text class="nj-int-text" x="16" y="98">A minor or patch release of 3.x does not break code that uses '
             'the public A&#8203;PI, unless that code opts in with a macro.</text>')
    s.append('<text class="nj-int-text" x="16" y="118">4.0 is not developed on a separate branch: it switches the '
             'defaults of these macros and removes the macros.</text>')
    # header
    hy = TOP - 18
    s.append('<text class="fg-h" x="32" y="%d">Macro</text>' % hy)
    s.append('<text class="fg-h" x="380" y="%d">added</text>' % hy)
    s.append('<text class="fg-h" x="500" y="%d" text-anchor="middle">3.x default</text>' % hy)
    s.append('<text class="nj-int-mute" x="632" y="%d" text-anchor="middle">define to try today</text>' % hy)
    s.append('<text class="fg-h" x="764" y="%d" text-anchor="middle">4.0 default</text>' % hy)
    for i, r in enumerate(rows):
        y = TOP + i * ROW + ROW / 2
        s.append('<rect class="nj-int-row" x="16" y="%g" width="848" height="%d" rx="6"/>' % (y - ROW / 2 + 2, ROW - 4))
        s.append('<text class="nj-int-macro" x="32" y="%g">%s</text>' % (y + 4.5, r["macro"]))
        s.append('<text class="nj-int-mute" x="380" y="%g">%s</text>' % (y + 4.5, r["added"]))
        s.append('<rect class="nj-int-pill" x="470" y="%g" width="60" height="22" rx="11"/>' % (y - 11))
        s.append('<text class="nj-int-val" x="500" y="%g" text-anchor="middle">%s</text>' % (y + 4.5, r["default"]))
        s.append('<line class="fg-arrow fg-arrow--dash" x1="544" y1="%g" x2="724" y2="%g" '
                 'marker-end="url(#nj-int-arrow)"/>' % (y, y))
        s.append('<rect class="nj-int-pill nj-int-pill--v4" x="728" y="%g" width="72" height="22" rx="11"/>' % (y - 11))
        if r["removed"]:
            s.append('<text class="nj-int-val nj-int-val--v4" x="764" y="%g" text-anchor="middle">removed</text>' % (y + 4.5))
        else:
            s.append('<text class="nj-int-val nj-int-val--v4" x="764" y="%g" text-anchor="middle">%s</text>' % (y + 4.5, r["v4"]))
    s.append('<text class="nj-int-mute" x="16" y="%d">Versions on the 3.x lane are the ones that added a macro, '
             'not to scale. &#8220;removed&#8221;: see the 4.0 behavior column of the table.</text>' % (H - 8))
    s.append('</svg>')
    return "\n".join(s) + "\n"


rows = parse(PAGE.read_text(encoding="utf-8"))
(OUT / "roadmap_lanes.svg").write_text(draw(rows), encoding="utf-8")
print("wrote", OUT / "roadmap_lanes.svg", "with", len(rows), "macros")
