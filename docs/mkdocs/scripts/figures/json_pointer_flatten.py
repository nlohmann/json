"""Draws the flatten()/unflatten() illustration of features/json_pointer.md as an inline SVG into docs/images/.

The SVG is not an image: the page includes its text with `--8<-- "images/json_pointer_flatten.svg"`, so it picks up
the colours and fonts of the page (see the `nj-fig` rules in docs/css/brand.css and the `nj-pointer` rules in
docs/css/fig-pointer.css). Run `python3 scripts/figures/json_pointer_flatten.py` from docs/mkdocs after changing the
drawing, and commit the generated file. In SVG text write the word JSON as `J&#8203;SON`, otherwise the abbreviation
extension wraps it in an <abbr> and the text disappears.

Left: the example document of the page as a tree. Right: the flat object that flatten() returns, one key per leaf.
Each leaf is joined to its flat key by a connector; leaf, connector and flat value share the colour of the value type
(string, number, boolean) used by the code highlighting.
"""
import html
from pathlib import Path

OUT = Path(__file__).resolve().parents[2] / "docs" / "images"
CW = 9.6      # JetBrains Mono advance at 16px
ROW = 28
Y0 = 92       # baseline of the first tree row
X0 = 20       # x of the root label
IND = 26      # indentation per level

# (depth, label, value or None, value type, flat key)
TREE = [
    (0, "root", None, None, None),
    (1, '"array"', None, None, None),
    (2, "0", '"A"', "s", "/array/0"),
    (2, "1", '"B"', "s", "/array/1"),
    (2, "2", '"C"', "s", "/array/2"),
    (1, '"nested"', None, None, None),
    (2, '"one"', "1", "n", "/nested/one"),
    (2, '"two"', "2", "n", "/nested/two"),
    (2, '"three"', None, None, None),
    (3, "0", "true", "b", "/nested/three/0"),
    (3, "1", "false", "b", "/nested/three/1"),
]
W = 760
FX = 470      # x of the flat keys


def esc(s):
    return html.escape(s, quote=False)


def main():
    body = []
    H = Y0 + (len(TREE) - 1) * ROW + 70
    mid = "fig-flat-arrow"
    defs = ('<defs><marker id="%s" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
            'orient="auto"><path class="fg-head" d="M0 1 L10 5 L0 9 z"/></marker></defs>' % mid)

    body.append('<text class="fg-h" x="%d" y="26">nested value</text>' % X0)
    body.append('<text class="fg-h" x="%d" y="26">flat object: key = J&#8203;SON Pointer</text>' % FX)

    # flatten() arrow on top, unflatten() arrow at the bottom
    ax1, ax2 = 250, FX - 20
    body.append('<line class="fg-arrow" x1="%d" y1="52" x2="%d" y2="52" marker-end="url(#%s)"/>' % (ax1, ax2, mid))
    body.append('<text class="nj-pointer-fl-op" x="%d" y="44">flatten()</text>' % ((ax1 + ax2) // 2))
    yb = H - 22
    body.append('<line class="fg-arrow" x1="%d" y1="%d" x2="%d" y2="%d" marker-end="url(#%s)"/>' % (ax2, yb, ax1, yb, mid))
    body.append('<text class="nj-pointer-fl-op" x="%d" y="%d">unflatten()</text>' % ((ax1 + ax2) // 2, yb - 8))

    # tree: elbow lines from each node to its parent
    rows = []
    parents = []
    for i, (d, label, val, typ, key) in enumerate(TREE):
        y = Y0 + i * ROW
        x = X0 + d * IND
        while parents and parents[-1][0] >= d:
            parents.pop()
        if parents:
            px = X0 + parents[-1][0] * IND + 5
            py = parents[-1][1] + 7
            body.append('<path class="nj-pointer-fl-edge" d="M%d %d V%d H%d"/>' % (px, py, y - 5, x - 4))
        parents.append((d, y))
        rows.append((x, y, label, val, typ, key))

    leaves = [r for r in rows if r[3] is not None]
    # flat keys: seven consecutive rows, centred on the leaf rows (tree rows 2 to 10)
    for j, (x, y, label, val, typ, key) in enumerate(leaves):
        fy = Y0 + (3 + j) * ROW
        lx = x + CW * (len(label) + 2 + len(val)) + 10
        body.append('<path class="nj-pointer-fl-link nj-pointer-fl--%s" d="M%g %d C%g %d %g %d %d %d"/>'
                    % (typ, lx, y - 5, lx + 120, y - 5, FX - 130, fy - 5, FX - 10, fy - 5))
        body.append('<circle class="nj-pointer-fl-dot nj-pointer-fl--%s" cx="%g" cy="%d" r="3.5"/>' % (typ, lx, y - 5))
        body.append('<text class="fg-code" x="%d" y="%d" xml:space="preserve"><tspan class="nj-pointer-fl-key">"%s"</tspan>: '
                    '<tspan class="nj-pointer-fl-v nj-pointer-fl--%s">%s</tspan></text>' % (FX, fy, esc(key), typ, esc(val)))

    for x, y, label, val, typ, key in rows:
        if val is None:
            cls = "fg-code nj-pointer-fl-inner" if label != "root" else "fg-h"
            body.append('<text class="%s" x="%d" y="%d">%s</text>' % (cls, x, y, esc(label)))
        else:
            body.append('<text class="fg-code" x="%d" y="%d" xml:space="preserve"><tspan class="nj-pointer-fl-k">%s</tspan>: '
                        '<tspan class="nj-pointer-fl-v nj-pointer-fl--%s">%s</tspan></text>' % (x, y, esc(label), typ, esc(val)))

    title = ("flatten() turns the nested example document into a flat object, and unflatten() turns it back. "
             "Left, the document as a tree: array with the elements A, B, C, and nested with one = 1, two = 2, and "
             "three with the elements true and false. Right, the flat object with one key per leaf: /array/0 = A, "
             "/array/1 = B, /array/2 = C, /nested/one = 1, /nested/two = 2, /nested/three/0 = true, "
             "/nested/three/1 = false. Each leaf is joined to its key by a line.")
    s = ['<svg class="nj-fig nj-pointer-fl" viewBox="0 0 %d %d" role="img" aria-labelledby="fig-flat-title" '
         'xmlns="http://www.w3.org/2000/svg">' % (W, H),
         '<title id="fig-flat-title">%s</title>' % esc(title), defs]
    s += body
    s.append('</svg>')
    (OUT / "json_pointer_flatten.svg").write_text("\n".join(s) + "\n")


main()
