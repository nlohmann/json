"""Draws the chunk-buffering strip of the large-input page as an inline SVG into docs/images/.

The strip follows docs/examples/partial_input_buffering.cpp: five chunks are appended to a buffer, and after each one
the whole buffer is parsed again. A parse error whose byte is one past the buffer size means the input ended early
(wait for more); an error before the end is a real syntax error. The byte positions were checked by running the
example (4/5, 12/13, 19/20, 30/31, complete at 35; `[1, ]` fails at byte 5).

The SVG is not an image: features/parsing/large_and_partial_input.md includes its text with
`--8<-- "images/chunk_buffering.svg"`, so it picks up the colours and fonts of the page (see the `nj-fig` rules in
docs/css/brand.css and the `nj-sax-` rules in docs/css/fig-sax.css). Run `python3 scripts/figures/chunk_buffering.py`
from docs/mkdocs after changing the drawing, and commit the generated file. In SVG text write the word JSON as
`J&#8203;SON`, otherwise the abbreviation extension wraps it in an <abbr> and the text disappears.
"""
import html
from pathlib import Path

OUT = Path(__file__).resolve().parents[2] / "docs" / "images"

CW = 8.4                  # JetBrains Mono advance at 14px
TX = 96                   # x of the buffer text
SX = 420                  # x of the result column
ROW = 50
CHUNKS = ['{"na', 'me": "Ma', 'ry", "l', 'ist": [1, 2', ', 3]}']


def esc(s):
    return html.escape(s).replace("J&amp;#8203;SON", "J&#8203;SON")


def row(body, y, label, old, new, err_byte, status, status_cls, note):
    body.append('<text class="fg-note fg-note--l" x="16" y="%g">%s</text>' % (y + 5, esc(label)))
    if old:
        body.append('<rect class="nj-sax-old" x="%g" y="%g" width="%g" height="24" rx="4"/>' % (TX - 3, y - 12, CW * len(old) + 3))
    body.append('<rect class="nj-sax-new" x="%g" y="%g" width="%g" height="24" rx="4"/>' % (TX + CW * len(old), y - 12, CW * len(new) + 3))
    body.append('<text class="nj-sax-buf" x="%g" y="%g" xml:space="preserve">%s</text>' % (TX, y + 5, esc(old + new)))
    if err_byte is not None:
        # the byte of a parse_error is 1-based: byte n is the character at index n - 1
        cx = TX + CW * (err_byte - 1) + CW / 2
        body.append('<path class="nj-sax-caret %s" d="M%g %g l-5 8 h10 z"/>' % (status_cls, cx, y + 14))
    body.append('<text class="nj-sax-status %s" x="%d" y="%g">%s</text>' % (status_cls, SX, y - 1, esc(status)))
    body.append('<text class="fg-note fg-note--l" x="%d" y="%g">%s</text>' % (SX, y + 15, esc(note)))


def main():
    W = 700
    body = []
    body.append('<text class="fg-h" x="16" y="24">chunk</text>')
    body.append('<text class="fg-h" x="%d" y="24">buffer, parsed from byte 1 each time</text>' % TX)
    body.append('<text class="fg-h" x="%d" y="24">result</text>' % SX)
    y, buf, parsed = 62, "", []
    for i, chunk in enumerate(CHUNKS):
        old, buf = buf, buf + chunk
        parsed.append(len(buf))
        if i < len(CHUNKS) - 1:
            row(body, y, "chunk %d" % (i + 1), old, chunk, len(buf) + 1,
                "error at byte %d = size + 1" % (len(buf) + 1), "nj-sax-s-wait", "incomplete: wait for more")
        else:
            row(body, y, "chunk %d" % (i + 1), old, chunk, None,
                "parsed, size %d" % len(buf), "nj-sax-s-ok", "complete: one value")
        y += ROW
    # the syntax error of the example, in a buffer of its own
    y += 8
    body.append('<path class="nj-sax-sep" d="M16 %g H%d"/>' % (y - 30, W - 16))
    row(body, y, "other input", "", "[1, ]", 5, "error at byte 5, size 5", "nj-sax-s-err", "before the end: a real error")
    y += 46
    total = " + ".join(str(n) for n in parsed)
    for k, line in enumerate(["Bytes parsed: %s = %d for a value of %d bytes." % (total, sum(parsed), parsed[-1]),
                              "Every attempt starts again at byte 1, so the total work grows",
                              "quadratically with the size of the value."]):
        body.append('<text class="fg-note fg-note--l" x="16" y="%g">%s</text>' % (y + 20 * k, esc(line)))
    y += 40
    H = int(y + 36)

    tid, did = "fig-sax-buf-title", "fig-sax-buf-desc"
    title = "Buffering chunks until the value is complete: five chunks of {\"name\": \"Mary\", \"list\": [1, 2, 3]} appended to a buffer."
    desc = ("After chunks 1 to 4 the buffer has 4, 12, 19, and 30 bytes, and parsing it fails at byte 5, 13, 20, and 31: "
            "one past the end, so the input is incomplete and the program waits for more. After chunk 5 the buffer of 35 "
            "bytes parses as one complete value. For the input [1, ] of 5 bytes the error is at byte 5, before the end, "
            "so it is a real syntax error. Every attempt parses the buffer from byte 1, so 4 + 12 + 19 + 30 + 35 = 100 "
            "bytes are parsed for a 35-byte value, and the work grows quadratically.")
    s = ['<svg class="nj-fig nj-fig--sax-buf" viewBox="0 0 %d %d" role="img" aria-labelledby="%s %s" '
         'xmlns="http://www.w3.org/2000/svg">' % (W, H, tid, did),
         '<title id="%s">%s</title>' % (tid, esc(title)),
         '<desc id="%s">%s</desc>' % (did, esc(desc))]
    s += body
    s.append("</svg>")
    (OUT / "chunk_buffering.svg").write_text("\n".join(s) + "\n")


main()
