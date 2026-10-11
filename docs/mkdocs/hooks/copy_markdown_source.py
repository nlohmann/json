"""Copy each documentation page's Markdown source into the built site."""

# Creates a `<path>.md` sibling of each HTML output (for example,
# `features/comments/` becomes `features/comments.md`) so agents and tools can
# fetch the raw Markdown directly instead of parsing rendered HTML. The
# `--8<-- "path"` lines of pymdownx.snippets are expanded with the extension's
# own preprocessor and the settings from mkdocs.yml, so the copies contain the
# included example code and files instead of the include directives.

import io
import os

import markdown
from pymdownx.snippets import SnippetMissingError

_pages = []
_snippets = None


def on_config(config):
    global _snippets
    md = markdown.Markdown(
        extensions=["pymdownx.snippets"],
        extension_configs={"pymdownx.snippets": config["mdx_configs"].get("pymdownx.snippets", {})},
    )
    _snippets = md.preprocessors["snippet"]
    _snippets.auto_append = []  # the glossary is only needed to render abbreviations
    return config


def on_files(files, config):
    global _pages
    _pages = [f for f in files if f.is_documentation_page()]
    return files


def on_post_build(config):
    site_dir = config["site_dir"]
    for file in _pages:
        url = file.url.rstrip("/")
        target = os.path.join(site_dir, (url or "index") + ".md")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with io.open(file.abs_src_path, encoding="utf-8", newline="") as source:
            text = source.read()
        try:
            text = "\n".join(_snippets.run(text.split("\n")))
        except (SnippetMissingError, OSError):
            pass  # keep the include directives; the regular build reports the missing file
        with io.open(target, "w", encoding="utf-8", newline="") as copy:
            copy.write(text)
