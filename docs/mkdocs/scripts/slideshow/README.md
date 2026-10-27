# Feature slideshow of the home page

`make` builds `docs/images/json-light.svg` and `json-dark.svg`, the animated feature tour on the home page. They replace
`json.gif` there. All text is outlined, so the SVGs need no fonts. Material's theme toggle cannot be seen from an
`<img>`, so the home page includes both files (`#only-light`, `#only-dark`) and Material shows the one that matches.

The slides are in [`slides.md`](slides.md): one `# Title` per slide (`{badge: TEXT}` at the end adds a red chip), `- `
bullets, and one fenced code block. `build.py` adds the title and closing slides around them, so the slide count follows
the file. Every snippet should compile against the current `develop`. Use a non-breaking space to keep words together
("16 bytes").

```bash
make          # download missing fonts, build both SVGs
make SECONDS=12
make clean    # remove the SVGs; make distclean also removes the fonts
```

Run it from this directory. It needs [uv](https://docs.astral.sh/uv/), plus curl, unzip and shasum for the fonts:
`build.py` declares its dependencies inline (PEP 723, pinned, so the output stays byte-identical) and `uv run --script`
provides them. `fonts/` is git-ignored: Inter (variable, Google Fonts repository) and JetBrains Mono 2.304 (variable)
are downloaded from pinned URLs and checked against their SHA-256; a changed upstream file stops the build.
`./build.py OUT.svg [seconds] [auto|light|dark]` works directly too. A mistake in `slides.md` stops the build with
`slides.md:LINE` and leaves the old SVGs in place.

Layout: title 48 px, bullets 24 px, code 19 px; the build warns when a slide's code would drop below 18 px. Syntax colours
are the `code-*` tokens of the brand (also used by `css/brand.css`). A CSS animation dissolves each slide over the
previous one and fills the progress bar; with reduced motion only the first slide shows.
