"""Draws the release timeline of home/releases/index.md as an inline SVG into docs/images/.

The releases and their dates come from the tables of that page (rows like `| [v3.11.2](v3.11.2.md) | 2022-08-12 | ...`),
so after adding a release to the page, run `python3 scripts/figures/release_timeline.py` from docs/mkdocs and commit
the regenerated docs/images/release_timeline.svg. The page includes the SVG text with
`--8<-- "images/release_timeline.svg"`, so it follows the light/dark toggle (see the `nj-fig` rules in
docs/css/brand.css and the `nj-int-*` rules in docs/css/fig-integration.css). Every marker has a <title> tooltip.
Rows without a date (the "Unreleased" row) are skipped; any other release row that cannot be parsed stops the script.
"""
import datetime
import re
import sys
from pathlib import Path

DOCS = Path(__file__).resolve().parents[2] / "docs"
OUT = Path(__file__).resolve().parents[2] / "docs" / "images"
PAGE = DOCS / "home" / "releases" / "index.md"

ROW = re.compile(r"^\|\s*\[v(\d+)\.(\d+)\.(\d+)\]\([^)]*\)\s*\|\s*([^|]*?)\s*\|")
W, LEFT, RIGHT = 880, 24, 856
LABEL_ROW, CHAR_W = 17, 7.0


def parse(markdown):
    releases = []
    for line in markdown.splitlines():
        if not line.startswith("| [v"):
            continue
        m = ROW.match(line)
        if not m:
            sys.exit("cannot parse release row: " + line)
        try:
            date = datetime.date.fromisoformat(m.group(4))
        except ValueError:
            sys.exit("cannot parse date in row: " + line)
        releases.append(((int(m.group(1)), int(m.group(2)), int(m.group(3))), date))
    if len(releases) < 2:
        sys.exit("found fewer than two releases in " + str(PAGE))
    if len({v for v, _ in releases}) != len(releases):
        sys.exit("duplicate release in " + str(PAGE))
    return sorted(releases, key=lambda r: (r[1], r[0]))


def name(version):
    return "v%d.%d.%d" % version


def draw(releases):
    first, last = releases[0][1], releases[-1][1]
    start, end = datetime.date(first.year, 1, 1), datetime.date(last.year + 1, 1, 1)
    span = (end - start).days

    def xof(date):
        return LEFT + (RIGHT - LEFT) * (date - start).days / span

    # minor labels, placed greedily into the lowest free row above the axis
    rows_end, labels = [], []
    for version, date in releases:
        if version[2] != 0:
            continue
        text = "%d.%d" % version[:2]
        x, half = xof(date), len(text) * CHAR_W / 2 + 2
        row = next((i for i, e in enumerate(rows_end) if e < x - half), None)
        if row is None:
            rows_end.append(0)
            row = len(rows_end) - 1
        rows_end[row] = x + half
        labels.append((x, row, text))
    top = 14 + LABEL_ROW * len(rows_end)
    axis = top + 12
    height = axis + 70

    s = ['<svg class="nj-fig nj-fig--timeline" viewBox="0 0 %d %d" role="img" aria-labelledby="nj-int-tl-title" '
         'xmlns="http://www.w3.org/2000/svg">' % (W, height)]
    minors = sum(1 for v, _ in releases if v[2] == 0)
    s.append('<title id="nj-int-tl-title">Timeline of the %d releases from %s (%s) to %s (%s): %d minor or major '
             'releases, drawn as filled dots with their version above the axis, and %d patch releases, drawn as '
             'rings.</title>' % (len(releases), name(releases[0][0]), first.isoformat(), name(releases[-1][0]),
                                 last.isoformat(), minors, len(releases) - minors))
    # year grid
    for year in range(start.year, end.year + 1):
        x = xof(datetime.date(year, 1, 1))
        s.append('<line class="nj-int-grid" x1="%.1f" y1="%d" x2="%.1f" y2="%d"/>' % (x, top - 4, x, axis + 8))
        if year < end.year:
            mid = xof(datetime.date(year, 7, 1))
            s.append('<text class="nj-int-year" x="%.1f" y="%d">%d</text>' % (mid, axis + 24, year))
    s.append('<line class="nj-int-axis" x1="%d" y1="%d" x2="%d" y2="%d"/>' % (LEFT, axis, RIGHT, axis))
    # major version spans
    majors = {}
    for version, date in releases:
        majors.setdefault(version[0], []).append(date)
    for major, dates in sorted(majors.items()):
        x0, x1 = xof(min(dates)), xof(max(dates))
        y = axis + 42
        s.append('<path class="nj-int-axis" fill="none" d="M%.1f %d V%d H%.1f V%d"/>' % (x0, y - 5, y, x1, y - 5))
        s.append('<text class="nj-int-major" x="%.1f" y="%d" text-anchor="%s">%d.x</text>'
                 % ((x0 + x1) / 2 if x1 - x0 > 30 else x0, y + 17, "middle" if x1 - x0 > 30 else "start", major))
    # leaders and labels
    for x, row, text in labels:
        y = top - row * LABEL_ROW
        s.append('<line class="nj-int-leader" x1="%.1f" y1="%d" x2="%.1f" y2="%d"/>' % (x, y + 3, x, axis - 7))
        s.append('<text class="nj-int-label" x="%.1f" y="%d">%s</text>' % (x, y, text))
    # markers: one per date, patch rings first so that minor dots stay on top
    by_date = {}
    for version, date in releases:
        by_date.setdefault(date, []).append(version)
    groups = sorted(by_date.items(), key=lambda g: any(v[2] == 0 for v in g[1]))
    for date, versions in groups:
        minor = any(v[2] == 0 for v in versions)
        x = xof(date)
        tip = ", ".join(name(v) for v in sorted(versions)) + " released " + date.isoformat()
        s.append('<g><title>%s</title><circle class="nj-int-hit" cx="%.1f" cy="%d" r="9"/>'
                 '<circle class="%s" cx="%.1f" cy="%d" r="%g"/></g>'
                 % (tip, x, axis, "nj-int-minor" if minor else "nj-int-patch", x, axis, 6 if minor else 3.5))
    s.append('</svg>')
    return "\n".join(s) + "\n"


releases = parse(PAGE.read_text(encoding="utf-8"))
(OUT / "release_timeline.svg").write_text(draw(releases), encoding="utf-8")
print("wrote", OUT / "release_timeline.svg", "with", len(releases), "releases")
