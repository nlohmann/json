"""Draws the quality-assurance pipeline overview of community/quality_assurance.md as an inline SVG into
docs/images/qa_pipeline.svg.

The SVG is not an image: the page includes its text with `--8<-- "images/qa_pipeline.svg"`, so it picks up the colours
and fonts of the page (see the `nj-fig` rules in docs/css/brand.css and the `nj-exceptions-*` rules in
docs/css/fig-exceptions.css). The file holds two drawings, a three-column one and a one-column one for phones; the CSS
shows one of them.

The lanes, tools and counts are taken from the text of community/quality_assurance.md, the trigger badges from the
`on:` sections of .github/workflows/*.yml. Update LANES when the page changes, run
`python3 scripts/figures/qa_pipeline.py` from docs/mkdocs, and commit the generated file. In SVG text write the word
JSON as `J&#8203;SON`, otherwise the abbreviation extension wraps it in an <abbr> and the text disappears.
"""
import html
import re
from pathlib import Path

OUT = Path(__file__).resolve().parents[2] / "docs" / "images"
P = "nj-exceptions-"

# trigger badges: key -> (label, css modifier)
TRIGGERS = {
    "push": ("every push / PR", "push"),
    "pr": ("every PR", "push"),
    "merge": ("before merge", "push"),
    "nightly": ("nightly", "sched"),
    "sched": ("scheduled", "sched"),
    "cont": ("continuous", "cont"),
}

# title, triggers, lines (at most 31 characters, so they fit a card of the three-column drawing)
LANES = [
    ("Build matrix", ["push", "merge"], [
        "50+ compilers: GCC, Clang, MSVC,",
        "AppleClang, Intel, NVIDIA, ...",
        "C++11, 14, 17, 20, 23, and 26",
        "libc++ and libstdc++",
        "warnings: Clang -Weverything,",
        "GCC 300+ warnings",
        "a subset on every push and PR,",
        "all before merge; Intel, NVIDIA,",
        "CUDA, and ARM64 nightly",
    ]),
    ("Unit tests (doctest)", ["push"], [
        "every public API function",
        "every exception id and message",
        "all Unicode code points",
        "single header and split headers",
        "custom number, string, array,",
        "and object types",
    ]),
    ("Coverage", ["nightly"], [
        "unit tests cover all lines",
        "of the code base",
    ]),
    ("Static analysis", ["push", "sched"], [
        "Clang-Tidy, Cppcheck, Infer",
        "Clang Static Analyzer (52",
        "checkers), IWYU, Codacy",
        "CodeQL, Semgrep, Flawfinder",
        "(also scheduled); Infer nightly",
    ]),
    ("Dynamic analysis", ["push", "nightly"], [
        "runtime assertions",
        "Valgrind (Memcheck), nightly",
        "address and undefined behavior",
        "sanitizers, integer overflow,",
        "nullability violations",
    ]),
    ("Fuzzing", ["pr", "cont"], [
        "CIFuzz on every pull request",
        "OSS-Fuzz: billions of inputs",
        "every crash fixed with a",
        "reproducing unit test",
    ]),
    ("Style", ["push"], [
        "Artistic Style (astyle),",
        "enforced in the CI",
        "cpplint with 61 rules",
    ]),
    ("Docs and examples", ["push", "sched"], [
        "every documentation example is",
        "tested; changed output fails",
        "site built with warnings",
        "as errors; links checked",
        "regularly (scheduled)",
    ]),
    ("Integration, supply chain", ["push", "sched"], [
        "CMake 3.5, 3.31.6, and 4.0.0",
        "Meson, Swift Package Manager",
        "dependency review on every PR",
        "Dependabot daily, OpenSSF",
        "Scorecard, REUSE",
    ]),
]


GLOSSARY = Path(__file__).resolve().parents[2] / "includes" / "glossary.md"
ABBRS = sorted(re.findall(r"^\*\[([^\]]+)\]:", GLOSSARY.read_text(), re.M), key=len, reverse=True)


def noabbr(s):
    """Breaks every glossary abbreviation with a zero-width space, so the abbr extension leaves SVG text alone."""
    for a in ABBRS:
        s = re.sub(r"(?<![\w&#])%s(?!\w)" % re.escape(a), a[0] + "&#8203;" + a[1:], s)
    return s


def esc(s):
    return html.escape(s, quote=True)


def txt(s):
    return noabbr(esc(s))


def badge_w(label):
    return len(label) * 6.3 + 16


def card(x, y, w, h, title, triggers, lines):
    s = ['<g class="%scard">' % P,
         '<rect class="%sbox" x="%g" y="%g" width="%g" height="%g" rx="8"/>' % (P, x, y, w, h),
         '<text class="%sctitle" x="%g" y="%g">%s</text>' % (P, x + 14, y + 25, txt(title))]
    bx = x + 14
    for t in triggers:
        label, mod = TRIGGERS[t]
        bw = badge_w(label)
        s.append('<rect class="%sbadge %sbadge--%s" x="%g" y="%g" width="%g" height="20" rx="10"/>' % (P, P, mod, bx, y + 36, bw))
        s.append('<text class="%sbadgetext %sbadgetext--%s" x="%g" y="%g">%s</text>' % (P, P, mod, bx + bw / 2, y + 50, txt(label)))
        bx += bw + 6
    for i, line in enumerate(lines):
        s.append('<text class="%sline" x="%g" y="%g">%s</text>' % (P, x + 14, y + 78 + i * 18, txt(line)))
    s.append('</g>')
    return "\n".join(s)


def pill(cx, y, w, label, sub=None, cls=""):
    h = 46 if sub else 34
    s = ['<rect class="%sstage%s" x="%g" y="%g" width="%g" height="%d" rx="%g"/>' % (P, cls, cx - w / 2, y, w, h, h / 2),
         '<text class="%sstagetext" x="%g" y="%g">%s</text>' % (P, cx, y + 22, txt(label))]
    if sub:
        s.append('<text class="%sstagesub" x="%g" y="%g">%s</text>' % (P, cx, y + 38, txt(sub)))
    return "\n".join(s), h


def arrow(x, y1, y2, mid):
    return '<line class="%sedge" x1="%g" y1="%g" x2="%g" y2="%g" marker-end="url(#%s)"/>' % (P, x, y1, x, y2, mid)


def drawing(W, cols, suffix):
    mid = "nj-qa-arrow-" + suffix
    body = []
    cx = W / 2
    s, h = pill(cx, 8, 230, "push or pull request")
    body.append(s)
    y = 8 + h
    body.append(arrow(cx, y, y + 26, mid))
    # container with the lanes
    top = y + 28
    pad, gap = 14, 12
    cw = (W - 24 - 2 * pad - (cols - 1) * gap) / cols
    body.append('<text class="%sgroup" x="%g" y="%g">checks, run in parallel on GitHub Actions and AppVeyor</text>' % (P, 12 + pad, top + 24) if cols > 1 else
                '<text class="%sgroup" x="%g" y="%g">checks, run in parallel</text>' % (P, 12 + pad, top + 24))
    gy = top + 40
    rows = [LANES[i:i + cols] for i in range(0, len(LANES), cols)]
    for r in rows:
        ch = 78 + 18 * (max(len(l[2]) for l in r) - 1) + 16
        for j, (title, trig, lines) in enumerate(r):
            body.append(card(12 + pad + j * (cw + gap), gy, cw, ch, title, trig, lines))
        gy += ch + gap
    bottom = gy - gap + pad
    body.insert(0, '<rect class="%sgroupbox" x="12" y="%g" width="%g" height="%g" rx="12"/>' % (P, top, W - 24, bottom - top))
    # after the checks
    body.append(arrow(cx, bottom, bottom + 26, mid))
    s, h = pill(cx, bottom + 28, 230, "merge into develop", cls=" %sstage--merge" % P)
    body.append(s)
    y = bottom + 28 + h
    body.append(arrow(cx, y, y + 26, mid))
    s, h = pill(cx, y + 28, 300, "release", "no open vulnerability alert", cls=" %sstage--merge" % P)
    body.append(s)
    H = y + 28 + h + 8
    defs = ('<defs><marker id="%s" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">'
            '<path class="fg-head" d="M0 1 L10 5 L0 9 z"/></marker></defs>' % mid)
    tid, did = "nj-qa-title-" + suffix, "nj-qa-desc-" + suffix
    desc = ("A push or pull request starts these checks; the badges say when each runs: " +
            "; ".join("%s (%s): %s" % (t, ", ".join(TRIGGERS[k][0] for k in trig), " ".join(lines)) for t, trig, lines in LANES) +
            ". When they pass, the change is merged into develop; a release is made only when no vulnerability alert is open.")
    out = ['<svg class="nj-fig %sqa %sqa--%s" viewBox="0 0 %d %d" role="img" aria-labelledby="%s %s" xmlns="http://www.w3.org/2000/svg">'
           % (P, P, "narrow" if cols == 1 else "wide", W, H, tid, did),
           '<title id="%s">Quality assurance pipeline</title>' % tid,
           '<desc id="%s">%s</desc>' % (did, txt(desc)),
           defs] + body + ['</svg>']
    return "\n".join(out)


def main():
    (OUT / "qa_pipeline.svg").write_text(drawing(760, 3, "w") + "\n" + drawing(360, 1, "n") + "\n")


main()
