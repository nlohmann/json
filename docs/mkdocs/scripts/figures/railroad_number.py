"""Draws the JSON number railroad diagram as an inline SVG into docs/images/.

The SVG is not an image: the pages include its text with `--8<-- "images/json_syntax_number.svg"`, so it picks up the colours and fonts of the
page (see the `railroad` and `nj-fig` rules in docs/css/brand.css). Run `python3 scripts/figures/railroad_number.py` from docs/mkdocs after
changing the drawing, and commit the generated file. In SVG text write the word JSON as `J&#8203;SON`, otherwise the
abbreviation extension wraps it in an <abbr> and the text disappears.
"""
import math
from pathlib import Path

OUT = Path(__file__).resolve().parents[2] / "docs" / "images"
Y0, Y1, Y2, Y3 = 44, 92, 136, 180
R = 10
paths, shapes, texts = [], [], []

def rounded(pts, r=R):
    d = "M%g %g" % pts[0]
    for i in range(1, len(pts) - 1):
        (x0, y0), (x1, y1), (x2, y2) = pts[i-1], pts[i], pts[i+1]
        l1 = math.hypot(x1-x0, y1-y0); l2 = math.hypot(x2-x1, y2-y1)
        rr = min(r, l1/2, l2/2)
        ax, ay = x1 - (x1-x0)/l1*rr, y1 - (y1-y0)/l1*rr
        bx, by = x1 + (x2-x1)/l2*rr, y1 + (y2-y1)/l2*rr
        d += " L%g %g Q%g %g %g %g" % (ax, ay, x1, y1, bx, by)
    d += " L%g %g" % pts[-1]
    return d

def path(*pts): paths.append(rounded(list(pts)))
def circle(cx, cy, ch):
    shapes.append('<circle class="rr-bg" cx="%g" cy="%g" r="13"/>' % (cx, cy))
    shapes.append('<circle class="rr-t" cx="%g" cy="%g" r="13"/>' % (cx, cy))
    texts.append('<text class="rr-c" x="%g" y="%g">%s</text>' % (cx, cy+5, ch))
def box(x0, x1, cy, label):
    shapes.append('<rect class="rr-bg" x="%g" y="%g" width="%g" height="28" rx="6"/>' % (x0, cy-14, x1-x0))
    shapes.append('<rect class="rr-n" x="%g" y="%g" width="%g" height="28" rx="6"/>' % (x0, cy-14, x1-x0))
    texts.append('<text class="rr-b" x="%g" y="%g">%s</text>' % ((x0+x1)/2, cy+5, label))
def loop(xr, xl, cy):  # return path below a box row
    path((xr, cy), (xr, cy+34), (xl, cy+34), (xl, cy))

# start / main
path((8, Y0), (850, Y0))
# A: optional minus
path((24, Y0), (38, Y0), (38, Y1), (59, Y1)); circle(72, Y1, "&#8722;"); path((85, Y1), (106, Y1), (106, Y0), (120, Y0))
# B: 0 | 1-9 digit*
circle(257, Y0, "0")
path((120, Y0), (134, Y0), (134, Y1), (160, Y1)); box(160, 242, Y1, "digit 1&#8211;9")
path((242, Y1), (380, Y1), (380, Y0), (396, Y0))
path((242, Y1), (258, Y1), (258, Y2), (278, Y2)); box(278, 332, Y2, "digit")
path((332, Y2), (348, Y2), (348, Y1)); loop(340, 270, Y2)
# C: fraction
path((396, Y0), (410, Y0), (410, Y1), (425, Y1)); circle(438, Y1, ".")
path((451, Y1), (462, Y1)); box(462, 516, Y1, "digit"); loop(524, 456, Y1)
path((516, Y1), (530, Y1), (530, Y0), (546, Y0))
# D: exponent
path((546, Y0), (560, Y0), (560, Y1), (577, Y1)); circle(590, Y1, "e")
path((546, Y0), (560, Y0), (560, Y2), (577, Y2)); circle(590, Y2, "E")
path((603, Y1), (728, Y1)); path((603, Y2), (620, Y2), (620, Y1))
path((640, Y1), (654, Y1), (654, Y2), (670, Y2)); circle(683, Y2, "&#8722;")
path((640, Y1), (654, Y1), (654, Y3), (670, Y3)); circle(683, Y3, "+")
path((696, Y2), (712, Y2), (712, Y1)); path((696, Y3), (712, Y3), (712, Y1))
path((728, Y1), (746, Y1)); box(746, 800, Y1, "digit"); loop(808, 738, Y1)
path((800, Y1), (816, Y1), (816, Y0), (832, Y0))

svg = ['<svg class="railroad" viewBox="0 0 860 214" role="img" aria-labelledby="rr-title" xmlns="http://www.w3.org/2000/svg">',
 '<title id="rr-title">Railroad diagram of the J&#8203;SON number syntax: optional minus, then 0 or a digit from 1 to 9 followed by digits, then an optional fraction (a dot and digits) and an optional exponent (e or E, an optional sign, and digits).</title>',
 '<g class="rr-track" fill="none" stroke="currentColor" stroke-opacity=".6" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">']
for d in paths: svg.append('<path d="%s"/>' % d)
svg.append('</g>')
svg.append('<polygon class="rr-arrow" points="2,%d 12,%d 2,%d"/>' % (Y0-6, Y0, Y0+6))
svg.append('<polygon class="rr-arrow" points="846,%d 858,%d 846,%d"/>' % (Y0-6, Y0, Y0+6))
svg += shapes + texts
svg.append('<text class="rr-l rr-name" x="24" y="%d">number</text>' % (Y0-12))
svg.append('<text class="rr-l" x="420" y="%d">fraction</text>' % (Y0-12))
svg.append('<text class="rr-l" x="580" y="%d">exponent</text>' % (Y0-12))
svg.append('</svg>')
open(OUT / "json_syntax_number.svg", "w").write("\n".join(svg) + "\n")
