"""Copy each documentation page's Markdown source into the built site."""

# Creates a `<path>.md` sibling of each HTML output (for example,
# `features/comments/` becomes `features/comments.md`) so agents and tools can
# fetch the raw Markdown directly instead of parsing rendered HTML.

import os
import shutil

_pages = []


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
        shutil.copyfile(file.abs_src_path, target)
