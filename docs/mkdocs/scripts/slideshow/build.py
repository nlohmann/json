#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = ["fonttools==4.67.0", "uharfbuzz==0.57.0"]
# ///
"""Animated SVG slideshow prototype for nlohmann/json, all text outlined (harfbuzz shaping, glyphs as <path> + <use>).

Usage: uv run --script build.py OUT.svg [seconds-per-slide] [auto|light|dark]

auto (the default) follows prefers-color-scheme. light and dark fix the colours, for pages with their own theme
toggle (MkDocs Material), which an <img> cannot see.

The pinned versions keep the output byte-identical; a different harfbuzz may shape slightly differently.
"""
import re, sys, os
import uharfbuzz as hb
from fontTools.pens.svgPathPen import SVGPathPen

HERE = os.path.dirname(os.path.abspath(__file__))
FONTS = os.path.join(HERE, "fonts")
W, H = 1200, 675
TOTAL = 0           # number of slides, set once slides.md is read (for the "02 / 20" labels and the progress segments)

# ---------------------------------------------------------------- glyphs

class Face:
    def __init__(self, file, key, feats=None):
        blob = hb.Blob.from_file_path(os.path.join(FONTS, file))
        self.face = hb.Face(blob)
        self.upem = self.face.upem
        self.key = key
        self.feats = feats or {}

    def font(self, var):
        f = hb.Font(self.face)
        f.set_variations(var)
        return f


INTER = Face("Inter.ttf", "i", {"cv11": True, "ss03": True, "kern": True})
MONO = Face("JetBrainsMono.ttf", "m", {"calt": False, "liga": False})

GLYPHS = {}         # (face, var, gid) -> id
DEFS = []


def gid_ref(face, font, var, gid):
    k = (face.key, tuple(sorted(var.items())), gid)
    if k not in GLYPHS:
        pen = SVGPathPen(None, ntos=lambda v: str(round(v)))
        font.draw_glyph_with_pen(gid, pen)
        d = pen.getCommands()
        gidname = f"g{len(GLYPHS):x}"
        GLYPHS[k] = gidname if d else None
        if d:
            DEFS.append(f'<path id="{gidname}" d="{d}"/>')
    return GLYPHS[k]


def shape(face, text, wght, size, track=0.0):
    if not text:
        return [], 0, face.upem
    var = {"wght": wght}
    if face is INTER:
        var["opsz"] = max(14, min(32, size))
    font = face.font(var)
    buf = hb.Buffer()
    buf.add_str(text)
    buf.guess_segment_properties()
    hb.shape(font, buf, face.feats)
    out, x = [], 0
    tr = track * face.upem
    for info, pos in zip(buf.glyph_infos, buf.glyph_positions):
        out.append((gid_ref(face, font, var, info.codepoint), x + pos.x_offset, pos.y_offset))
        x += pos.x_advance + tr
    return out, x - tr, face.upem


def width(text, face=INTER, wght=400, size=16, track=0.0):
    _, w, upem = shape(face, text, wght, size, track)
    return w * size / upem


def run(text, x, y, size, wght=400, cls="tx", face=INTER, track=0.0):
    """One line of text, baseline at y. Returns (svg, width_px)."""
    glyphs, w, upem = shape(face, text, wght, size, track)
    s = size / upem
    uses = "".join(f'<use href="#{g}" x="{gx}"' + (f' y="{-gy}"' if gy else "") + "/>"
                   for g, gx, gy in glyphs if g)
    return (f'<g class="{cls}" transform="translate({x:g} {y:g}) scale({s:.6g} {-s:.6g})">{uses}</g>', w * s)


def runs(parts, x, y, size, face=INTER, track=0.0):
    """Several (text, wght, cls) pieces on one line."""
    out = []
    for text, wght, cls in parts:
        svg, w = run(text, x, y, size, wght, cls, face, track)
        out.append(svg)
        x += w + track * size
    return "".join(out), x


def wrap(text, maxw, size, wght=400):
    lines = _wrap(text, maxw, size, wght)
    # no one-word widow: pull the last word of the previous line down if it still fits
    if len(lines) > 1 and " " not in lines[-1] and " " in lines[-2]:
        head, last = lines[-2].rsplit(" ", 1)
        if width(last + " " + lines[-1], size=size, wght=wght) <= maxw:
            lines[-2:] = [head, last + " " + lines[-1]]
    return lines


def _wrap(text, maxw, size, wght=400):
    lines, cur = [], ""
    for word in text.split(" "):
        t = (cur + " " + word).strip()
        if cur and width(t, size=size, wght=wght) > maxw:
            lines.append(cur)
            cur = word
        else:
            cur = t
    return lines + [cur]

# ---------------------------------------------------------------- pieces


def wordmark(x, y, size, on="page"):
    """The wordmark with hand kerning around the slash (see the logo in the brand kit). Below 32 px it switches to the
    small optical master (nlohmann 250 / slash 450), because Thin falls apart at footer size."""
    a, sl = ("wm-a", "wm-s") if on == "page" else ("on-a", "on-s")
    small = size < 32
    w = (250, 450, 800) if small else (100, 400, 800)
    k = (0.004, 0.024) if small else (-0.006, 0.012)
    out = []
    for i, (t, wg, c) in enumerate([("nlohmann", w[0], a), ("/", w[1], sl), ("json", w[2], a)]):
        svg, wd = run(t, x, y, size, wg, c, track=-0.02)
        out.append(svg)
        x += wd - 0.02 * size + (k[i] * size if i < 2 else 0)
    return "".join(out), x


KW = {"using", "auto", "return", "const", "struct", "for", "override"}
TYPES = {"int", "void", "bool", "double", "char", "float"}
CONSTANTS = {"true", "false", "nullptr"}
TOKEN = re.compile(r'(//.*$)|(R"\(.*?\)"|R"\(.*$|"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)\')|(<[\w/.]+>(?=\s*$))|(#\w+)'
                   r'|(\b\d+(?:\.\d+)?\b)|(\b[A-Za-z_]\w*\b)|(\s+)|(.)')


def code_block(lines, x, y, size, lh):
    """Lines of C++; a raw string literal may span lines."""
    out, in_raw = [], False
    for line in lines:
        if line:
            svg, in_raw = code_line(line, x, y, size, in_raw)
            out.append(svg)
            y += lh
        else:
            y += lh * BLANK
    return "".join(out)


BLANK = 0.55   # an empty code line is a paragraph break, not a full line


def code_height(lines, size, lh):
    n_full = sum(1 for l in lines if l)
    n_blank = len(lines) - n_full
    return lh * (n_full - 1) + lh * BLANK * n_blank + size


def code_line(line, x, y, size, in_raw=False):
    if line.startswith("$ "):
        return runs([("$ ", 400, "tx3"), (line[2:], 400, "tx")], x, y, size, MONO)[0], False
    out, cx = [], x
    if in_raw:
        end = line.find(')"')
        head = line if end < 0 else line[:end + 2]
        svg, w = run(head, cx, y, size, 400, "str", MONO)
        out.append(svg)
        if end < 0:
            return "".join(out), True
        cx += w
        line = line[end + 2:]
        in_raw = False
    for m in TOKEN.finditer(line):
        com, st, inc, pp, num, ident, ws, other = m.groups()
        t = m.group(0)
        if st and st.startswith('R"(') and not st.endswith(')"'):
            in_raw = True
        face, wght, cls = MONO, 400, "tx"
        if com:
            cls = "com"            # upright: JetBrains Mono Italic's cursive f reads as a florin at README size
        elif st or inc:
            cls = "str"
        elif pp:
            cls = "pp"
        elif ident in KW:
            wght, cls = 600, "kw"
        elif ident in TYPES:
            cls = "ty"
        elif num or ident in CONSTANTS:
            cls = "num"
        elif ident and line[m.end():m.end() + 1] == "(":
            cls = "fn"             # a call or definition: name directly followed by "("
        svg, w = run(t, cx, y, size, wght, cls, face)
        if not ws:
            out.append(svg)
        cx += w
    return "".join(out), in_raw


SEG, SEG_GAP = 20, 5


def progress(idx, n_proto, y):
    """TOTAL segments at the bottom right; earlier slides full, current one fills over the slide's time."""
    seg, gap = SEG, SEG_GAP
    x0 = W - 64 - TOTAL * seg - (TOTAL - 1) * gap
    out = []
    for k in range(TOTAL):
        x = x0 + k * (seg + gap)
        out.append(f'<rect class="seg" x="{x}" y="{y}" width="{seg}" height="3" rx="1.5"/>')
        if k < idx:
            out.append(f'<rect class="seg-on" x="{x}" y="{y}" width="{seg}" height="3" rx="1.5"/>')
        elif k == idx:
            out.append(f'<rect class="seg-on fill" x="{x}" y="{y}" width="{seg}" height="3" rx="1.5"/>')
    return "".join(out)


def pattern_def():
    tile = [("{", 14, 34), ("]", 92, 22), (":", 136, 60), ("[", 52, 82), (",", 118, 112),
            ("}", 20, 140), (":", 78, 150), ("{", 140, 158)]
    glyphs = "".join(run(c, x, y, 26, 600, "pat", MONO)[0] for c, x, y in tile)
    return f'<pattern id="pat" width="160" height="160" patternUnits="userSpaceOnUse">{glyphs}</pattern>'

# ---------------------------------------------------------------- slides


CODE_SIZES = []
SLOGAN = "What if JSON was part of modern C++?"


def band_bg():
    """Hero gradient plus the syntax pattern, faded out towards the text side (left)."""
    return ('<rect width="1200" height="675" fill="url(#hero)"/>'
            '<rect width="1200" height="675" fill="url(#pat)" mask="url(#patfade)"/>')


def footer_band(idx, n, left=None):
    out = []
    if left:
        out.append(run(left, 64, FOOT_Y, 20, 600, "on-tx")[0])
    out.append(progress(idx, n, FOOT_Y - 7.5).replace('class="seg"', 'class="seg on-band"').replace('class="seg-on', 'class="seg-on on-band'))
    return "".join(out)


FOOT_Y = 640      # one footer baseline on every slide: wordmark or URL left, progress right


def slide_title(idx, n):
    out = [band_bg()]
    x = 96
    label = "VERSION 3.13.0"
    lw = width(label, MONO, 500, 15, 0.04)
    out.append(f'<rect class="chip" x="{x}" y="186" width="{lw + 28:.1f}" height="34" rx="4"/>')
    out.append(run(label, x + 14, 208.5, 15, 500, "on-tx", MONO, 0.04)[0])
    out.append(wordmark(x - 6, 336, 112, on="band")[0])
    out.append(runs([("// ", 400, "w70"), (SLOGAN, 400, "on-s")], x, 404, 26, MONO)[0])
    out.append(footer_band(idx, n, "github.com/nlohmann/json"))
    return "".join(out)


def slide_feature(idx, n, title, bullets, code, badge=None):
    out = ['<rect class="bg" width="1200" height="675"/>']
    x, top, bottom = 64, 136, 596
    # title row: 48/800, -3 %
    svg, tw = run(title, x - 2, 98, 48, 800, "tx", track=-0.03)
    out.append(svg)
    if badge:
        cx = x + tw + 16
        cw = width(badge, MONO, 600, 13, 0.06) + 18
        out.append(f'<rect class="red" x="{cx:.1f}" y="68.5" width="{cw:.1f}" height="26" rx="4"/>')
        out.append(run(badge, cx + 9, 86.2, 13, 600, "on-tx", MONO, 0.06)[0])
    # code panel: fixed left edge, fixed width, fixed top on every slide; only its height follows the code
    pad, lf = 28, 1.45
    px, pw = 488, 1136 - 488
    em = max(width(l, MONO, 400, 1) for l in code)
    cs = 19.0
    while cs > 14 and (em * cs > pw - 2 * pad or code_height(code, cs, lf * cs) > bottom - top - 2 * pad):
        cs -= 0.5
    CODE_SIZES.append((title, cs))
    if cs < 18:
        print(f"  warning: {title!r} code at {cs} px ({em * 19:.0f} px wide at 19 px)", file=sys.stderr)
    lh = lf * cs
    ph = max(2 * pad + code_height(code, cs, lh), 240)
    out.append(f'<rect class="panel" x="{px}" y="{top}" width="{pw}" height="{ph:.0f}" rx="6"/>')
    first = top + pad + cs * 0.78
    out.append(code_block(code, px + pad, first, cs, lh))
    # bullets: 24/400 on 34, first baseline level with the first code baseline
    colw = px - x - 40
    by = first
    for b in bullets:
        out.append(f'<rect class="blk" x="{x}" y="{by - 10.6:.1f}" width="8" height="8" rx="1.5"/>')
        for line in wrap(b, colw - 24, 24):
            out.append(run(line, x + 24, by, 24, 400, "tx2")[0])
            by += 34
        by += 16
    # footer: small-master wordmark left, progress right, no rule, no numeral
    out.append(wordmark(64, FOOT_Y, 22)[0])
    out.append(progress(idx, n, FOOT_Y - 7.5))
    return "".join(out)


def slide_closing(idx, n):
    out = [band_bg()]
    x = 96
    out.append(wordmark(x - 4, 146, 80, on="band")[0])
    out.append(runs([("// ", 400, "w70"), (SLOGAN, 400, "on-s")], x, 200, 22, MONO)[0])
    info = [
        ("{", None),
        ('  "copyright": ', "(c) 2013-2026 Niels Lohmann"),
        ('  "license": ', "MIT"),
        ('  "docs": ', "json.nlohmann.me"),
        ('  "github": ', "github.com/nlohmann/json"),
        ('  "sponsor": ', "github.com/sponsors/nlohmann"),
        ('  "mail": ', "mail@nlohmann.me"),
        ("}", None),
    ]
    cs, lh, pad = 21, 33, 28
    py = 244
    pw = max(width(k + '"' + (v or "") + '",', MONO, 400, cs) for k, v in info) + 2 * pad
    out.append(f'<rect class="on-panel" x="{x}" y="{py}" width="{pw:.0f}" height="{2 * pad + lh * (len(info) - 1) + cs:.0f}" rx="6"/>')
    y = py + pad + cs * 0.8
    for k, (key, val) in enumerate(info):
        if val is None:
            out.append(run(key, x + pad, y, cs, 400, "on-tx", MONO)[0])
        else:
            comma = "," if k < len(info) - 2 else ""
            out.append(runs([(key, 400, "on-tx"), (f'"{val}"', 400, "on-s"), (comma, 400, "on-tx")], x + pad, y, cs, MONO)[0])
        y += lh
    out.append(footer_band(idx, n))
    return "".join(out)


def load_slides(path):
    """Feature slides from Markdown: '# Title {badge: TEXT}', '- bullet' lines, one fenced code block."""
    text = re.sub(r"<!--.*?-->", "", open(path).read(), flags=re.S)
    slides, cur, in_code = [], None, False
    for no, line in enumerate(text.split("\n"), 1):
        if in_code:
            if line.startswith("```"):
                in_code = False
            else:
                cur["code"].append(line)
        elif line.startswith("```"):
            in_code = True
        elif line.startswith("# "):
            title, badge = line[2:].strip(), None
            m = re.search(r"\s*\{badge:\s*(.*?)\}$", title)
            if m:
                title, badge = title[:m.start()], m.group(1)
            cur = {"title": title, "bullets": [], "code": [], "badge": badge}
            slides.append(cur)
        elif line.startswith("- ") and cur:
            cur["bullets"].append(line[2:].strip())
        elif line[:1] in " \t" and line.strip() and cur and cur["bullets"]:
            cur["bullets"][-1] += " " + line.strip()
        elif line.strip():
            raise SystemExit(f"{path}:{no}: unexpected line: {line!r}")
    for sl in slides:
        while sl["code"] and not sl["code"][-1].strip():
            sl["code"].pop()
        if not sl["code"]:
            raise SystemExit(f"{path}: slide {sl['title']!r} has no code block")
    return slides


FEATURES = load_slides(os.path.join(HERE, "slides.md"))


def _feature(f):
    return lambda i, n: slide_feature(i, n, f["title"], f["bullets"], f["code"], f["badge"])


SLIDES = [slide_title] + [_feature(f) for f in FEATURES] + [slide_closing]
TOTAL = len(SLIDES)


# ---------------------------------------------------------------- assemble


def build(sec):
    n = len(SLIDES)
    T = n * sec
    fade = 0.6
    a, b, c = fade / T * 100, sec / T * 100, (sec + fade) / T * 100
    def cls(i):
        return "s s0" if i == 0 else "s sl" if i == n - 1 else "s"
    bodies = [f'<g class="{cls(i)}" style="animation-delay:{i * sec:g}s">{fn(i, n)}</g>' for i, fn in enumerate(SLIDES)]
    css = f"""
.bg{{fill:#fff}} .tx{{fill:#0f1419}} .tx2{{fill:#3d444f}} .tx3{{fill:#8a919c}} .com{{fill:#646d7a}}
.bl{{fill:#1747a6}} .blk{{fill:#1747a6}} .kw{{fill:#1747a6}} .ty{{fill:#0d6e72}} .fn{{fill:#6b3fb8}} .str{{fill:#23793a}} .num{{fill:#b04a07}} .pp{{fill:#a3247a}}
.panel{{fill:#f5f7fa;stroke:#e3e6eb;stroke-width:1}} .rule{{stroke:#e3e6eb;stroke-width:1}}
.wm-a{{fill:#0f1419}} .wm-s{{fill:#1747a6}}
.on-a,.on-tx{{fill:#fff}} .red{{fill:#d93a3f}} .on-panel{{fill:#fff;fill-opacity:.08;stroke:#fff;stroke-opacity:.16}} .on-s{{fill:#bcd3fb}} .w70{{fill:#fff;fill-opacity:.7}} .on-tx2{{fill:#dbe6fb}} .chip{{fill:#fff;fill-opacity:.14}}
.pat{{fill:#fff;fill-opacity:.09}}
.h1{{stop-color:#1d55c4}} .h2{{stop-color:#123a8a}}
.seg{{fill:#e3e6eb}} .seg-on{{fill:#1747a6}}
.seg.on-band{{fill:#fff;fill-opacity:.25}} .seg-on.on-band{{fill:#fff;fill-opacity:1}}
@media (prefers-color-scheme:dark){{
 .bg{{fill:#0f1218}} .tx,.wm-a{{fill:#f2f4f7}} .tx2{{fill:#c3c8d1}} .tx3{{fill:#7b828e}} .com{{fill:#8b929e}}
 .bl,.blk,.wm-s,.seg-on,.kw{{fill:#7aa7f5}} .ty{{fill:#4fd1c5}} .fn{{fill:#c4a3ff}} .str{{fill:#7ed491}} .num{{fill:#f5a65b}} .pp{{fill:#f48fc8}}
 .panel{{fill:#171b23;stroke:#272c36}} .rule{{stroke:#272c36}} .seg{{fill:#272c36}}
 .red{{fill:#c8383d}} .h1{{stop-color:#163f93}} .h2{{stop-color:#0c2556}}
}}
.s{{opacity:0;animation:show {T:g}s linear infinite backwards}}
.fill{{transform-box:fill-box;transform-origin:left;animation:fill {T:g}s linear infinite backwards;animation-delay:inherit}}
.s0{{animation-name:show0}} .sl{{animation-name:showl}}
@keyframes show{{0%{{opacity:0;animation-timing-function:cubic-bezier(.2,.6,.2,1)}} {a:.4f}%{{opacity:1}} {c:.4f}%{{opacity:1}} {c + .01:.4f}%{{opacity:0}} 100%{{opacity:0}}}}
@keyframes show0{{0%{{opacity:1}} {c:.4f}%{{opacity:1}} {c + .01:.4f}%{{opacity:0}} 100%{{opacity:0}}}}
@keyframes showl{{0%{{opacity:0;animation-timing-function:cubic-bezier(.2,.6,.2,1)}} {a:.4f}%{{opacity:1}} {b:.4f}%{{opacity:1}} {c:.4f}%{{opacity:0}} 100%{{opacity:0}}}}
@keyframes fill{{0%{{transform:scaleX(0)}} {b:.4f}%{{transform:scaleX(1)}} 100%{{transform:scaleX(1)}}}}
@media (prefers-reduced-motion:reduce){{.s,.fill{{animation:none}} .s:first-of-type{{opacity:1}}}}
"""
    css = re.sub(r"\n\s*", "", css)
    pat = pattern_def()
    return (f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img">'
            f'<title>JSON for Modern C++: feature slideshow (animated, {n} slides, {sec:g} s each)</title>'
            f'<style>{css}</style>'
            f'<defs>{"".join(DEFS)}{pat}'
            f'<linearGradient id="hero" gradientTransform="rotate(70 .5 .5)"><stop class="h1" offset="0"/><stop class="h2" offset="1"/></linearGradient>'
            f'<linearGradient id="fadeg" x1="0" x2="1" y1="0" y2="0"><stop offset=".25" stop-color="#fff" stop-opacity="0"/><stop offset=".85" stop-color="#fff" stop-opacity="1"/></linearGradient>'
            f'<mask id="patfade" maskUnits="userSpaceOnUse" x="0" y="0" width="{W}" height="{H}"><rect width="{W}" height="{H}" fill="url(#fadeg)"/></mask></defs>'
            f'<rect class="bg" width="{W}" height="{H}"/>'
            f'{"".join(bodies)}</svg>')


def fix_scheme(svg, scheme):
    """Drop the dark-mode block (light) or apply it unconditionally (dark)."""
    if scheme == "auto":
        return svg
    start = svg.index("@media (prefers-color-scheme:dark){")
    i, depth = svg.index("{", start), 0
    for j in range(i, len(svg)):
        depth += {"{": 1, "}": -1}.get(svg[j], 0)
        if depth == 0:
            break
    inner = svg[i + 1:j] if scheme == "dark" else ""
    return svg[:start] + inner + svg[j + 1:]


if __name__ == "__main__":
    out = sys.argv[1]
    sec = float(sys.argv[2]) if len(sys.argv) > 2 else 15
    scheme = sys.argv[3] if len(sys.argv) > 3 else "auto"
    if scheme not in ("auto", "light", "dark"):
        sys.exit(f"unknown colour scheme {scheme!r}: use auto, light or dark")
    svg = fix_scheme(build(sec), scheme)
    # defs are appended while slides render, so build the slides first (done inside build via f-string order)
    open(out, "w").write(svg)
    print(out, len(svg.encode()) // 1024, "KB,", len(GLYPHS), "glyphs; code px:", " ".join(f"{c:g}" for _, c in CODE_SIZES))
