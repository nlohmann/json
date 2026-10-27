"""Draws the illustrative memory-over-time chart of the large-input page as an inline SVG into docs/images/.

The chart shows the qualitative shape of the memory use while a large array of records is parsed in four ways: parse()
builds the whole tree (DOM), a parser callback discards every record, a SAX handler keeps only what it needs, and a
json_document keeps the text plus its index. It is not a measurement: there are no numbers on the axes, and the
relative heights depend on the data.

The SVG is not an image: features/parsing/large_and_partial_input.md includes its text with
`--8<-- "images/memory_over_time.svg"`, so it picks up the colours and fonts of the page (see the `nj-fig` rules in
docs/css/brand.css and the `nj-sax-` rules in docs/css/fig-sax.css). Run `python3 scripts/figures/memory_over_time.py`
from docs/mkdocs after changing the drawing, and commit the generated file. In SVG text write the word JSON as
`J&#8203;SON` (likewise DOM and SAX, which esc() does), otherwise the abbreviation extension wraps it in an <abbr> and
the text disappears.
"""
import html
from pathlib import Path

OUT = Path(__file__).resolve().parents[2] / "docs" / "images"

W, H = 660, 312
X0, X1 = 56, 440          # plot area
Y0, Y1 = 48, 272          # top, baseline


def esc(s):
    # break the words of the glossary (includes/glossary.md) so the abbreviation extension leaves them alone
    s = html.escape(s)
    for word in ("DOM", "SAX", "JSON"):
        s = s.replace(word, word[0] + "&#8203;" + word[1:])
    return s


def main():
    body = []
    tid, did = "fig-sax-mem-title", "fig-sax-mem-desc"
    # axes
    body.append('<path class="nj-sax-axis" d="M%d %d V%d H%d"/>' % (X0, Y0 - 12, Y1, X1 + 8))
    body.append('<text class="fg-h" x="%d" y="24">memory</text>' % (X0 - 40))
    body.append('<text class="fg-note fg-note--l" x="%d" y="%d">time: records parsed</text>' % (X0, Y1 + 22))
    body.append('<text class="fg-note fg-note--r nj-sax-illus" x="%d" y="24">illustrative, not a measurement</text>' % (W - 12))

    # DOM: grows with every record until the whole tree is built
    body.append('<path class="nj-sax-curve nj-sax-c-dom" d="M%d %d L%d %d"/>' % (X0, Y1 - 4, X1, Y0 + 4))
    # json_document: the text is in memory from the start; the index grows while parsing
    yt, yi = 168, 146
    body.append('<path class="nj-sax-curve nj-sax-c-doc" d="M%d %d L%d %d"/>' % (X0, yt, X1, yi))
    # callback: one record at a time, released when it is discarded
    hi, lo, step = Y1 - 34, Y1 - 22, 32
    d, x = "M%d %d" % (X0, lo), X0
    while x + step <= X1:
        d += " L%d %d L%d %d" % (x + step, hi, x + step, lo)
        x += step
    body.append('<path class="nj-sax-curve nj-sax-c-cb" d="%s"/>' % d)
    # SAX: no value is built, only what the handler keeps
    body.append('<path class="nj-sax-curve nj-sax-c-sax" d="M%d %d H%d"/>' % (X0, Y1 - 8, X1))

    labels = [
        (Y0 + 9, "nj-sax-c-dom", "DOM: parse()", "the whole tree"),
        (yi + 5, "nj-sax-c-doc", "json_document", "the text plus its index"),
        (hi - 2, "nj-sax-c-cb", "callback, discard", "one record at a time"),
        (Y1 + 6, "nj-sax-c-sax", "SAX", "only what the handler keeps"),
    ]
    for y, cls, name, note in labels:
        body.append('<text class="nj-sax-lab %s" x="%d" y="%d">%s</text>' % (cls, X1 + 16, y - 9, esc(name)))
        body.append('<text class="fg-note fg-note--l" x="%d" y="%d">%s</text>' % (X1 + 16, y + 8, esc(note)))

    title = "Illustrative memory use over time while a large array of records is parsed, not a measurement."
    desc = ("Four curves. DOM, parse(): rises steadily until the whole tree is in memory. json_document: starts at about "
            "the size of the text, which it keeps, and grows a little while its index is built. Parser callback that "
            "discards every record: stays flat at the size of one record. SAX: stays flat and lowest, because no value "
            "is built and only what the handler keeps is in memory.")
    s = ['<svg class="nj-fig nj-fig--sax-mem" viewBox="0 0 %d %d" role="img" aria-labelledby="%s %s" '
         'xmlns="http://www.w3.org/2000/svg">' % (W, H, tid, did),
         '<title id="%s">%s</title>' % (tid, esc(title)),
         '<desc id="%s">%s</desc>' % (did, esc(desc))]
    s += body
    s.append("</svg>")
    (OUT / "memory_over_time.svg").write_text("\n".join(s) + "\n")


main()
