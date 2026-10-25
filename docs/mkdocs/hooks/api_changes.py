"""Generate the "API changes" section of the release pages from the version histories of the API pages."""

# Every page below docs/api ends in a "Version history" section ("Added in version 3.8.0.", "... since version 3.13.0.").
# This hook collects these entries and replaces the `<!-- api-changes -->` marker of each page in home/releases with
# the pages that were added in that release and the changes made to existing pages. The page of a release is named
# after its version (v3.12.0.md); unreleased.md collects all versions newer than the latest release. The result is an
# overview of what changed in the API, not a change log.

import logging
import os
import posixpath
import re

log = logging.getLogger("mkdocs.hooks.api_changes")

_DIR = "home/releases"
_PAGE_VERSION = re.compile(r"v(\d+)\.(\d+)\.(\d+)\.md")
_MARKER = "<!-- api-changes -->"
_HISTORY = re.compile(r"^## Version history\n(.*?)(?=^## |\Z)", re.DOTALL | re.MULTILINE)
_TITLE = re.compile(r"^# (.+)$", re.MULTILINE)
_ITEM = re.compile(r"^(?:[-*]|\d+\.)\s+")
_SENTENCE = re.compile(r"(?<=\.)\s+(?=[A-Z`\[])")
_VERSION = re.compile(r"\b(?:version|since|in)\s+(\d+)\.(\d+)\.(\d+)\b", re.IGNORECASE)
_FUTURE = re.compile(r"\bwill\b|\bplanned\b", re.IGNORECASE)  # statements about versions that do not exist yet
_NEXT_MAJOR = (4, 0, 0)  # versions from here on are announcements, not changes
_ADDED = re.compile(r"^(?:Added|Introduced)\b.*\bversion \d|^Since version \d+\.\d+\.\d+\.?$", re.IGNORECASE)
_LINK = re.compile(r"(\]\()([^)\s]+)(\))")


def on_page_markdown(markdown, *, page, config, files):
    uri = page.file.src_uri
    if posixpath.dirname(uri) != _DIR or _MARKER not in markdown:
        return markdown
    docs_dir = config["docs_dir"]
    entries = _collect(docs_dir)
    released = sorted(tuple(map(int, m.groups())) for m in
                      (_PAGE_VERSION.fullmatch(name) for name in os.listdir(os.path.join(docs_dir, _DIR))) if m)
    match = _PAGE_VERSION.fullmatch(posixpath.basename(uri))
    if match:
        versions = [tuple(map(int, match.groups()))]
    else:  # unreleased.md
        versions = sorted((v for v in entries if not released or v > released[-1]), reverse=True)
    return markdown.replace(_MARKER, _render(uri, [(v, entries[v]) for v in versions if v in entries]))


def _title(text, path):
    match = _TITLE.search(text)
    title = match.group(1) if match else os.path.splitext(os.path.basename(path))[0]
    title = re.sub(r"</?small>", "", title)
    title = title.replace("`", "").replace("\\", "").strip()
    return title[len("nlohmann::"):] if title.startswith("nlohmann::") else title


def _collect(docs_dir):
    """Return {version: {"added": [(title, uri)], "changed": [(title, uri, text)]}}."""
    result = {}
    api = os.path.join(docs_dir, "api")
    for root, _, names in sorted(os.walk(api)):
        for name in sorted(names):
            if not name.endswith(".md"):
                continue
            path = os.path.join(root, name)
            uri = posixpath.relpath(path.replace(os.sep, "/"), docs_dir.replace(os.sep, "/"))
            with open(path, encoding="utf-8") as source:
                text = source.read()
            history = _HISTORY.search(text)
            if not history:
                continue
            title = _title(text, path)
            found = _sentences(history.group(1))
            # a page is added in the earliest version named by an "Added in" sentence that opens an entry (an entry of
            # a numbered list describes one overload; later unnumbered entries extend an existing page)
            starts = [v for i, n, first, v, sentence in found if first and _ADDED.match(sentence) and (i == 0 or n)]
            added = min(starts) if starts else None
            page_added = False
            for index, number, first, version, sentence in found:
                if version >= _NEXT_MAJOR:
                    continue
                bucket = result.setdefault(version, {"added": [], "changed": []})
                opens = first and _ADDED.match(sentence) and (index == 0 or number)
                if opens and version == added:
                    if not page_added:
                        bucket["added"].append((title, uri))
                        page_added = True
                    continue
                if number and re.fullmatch(r"Added in version [\d.]+\.?", sentence):
                    sentence = f"Overload {number} added."
                elif number:
                    sentence = f"Overload {number}: {sentence}"
                if (title, uri, sentence) not in bucket["changed"]:
                    bucket["changed"].append((title, uri, sentence))
    return result


def _sentences(section):
    """Yield (entry index, overload number, opens entry, version, sentence) for every sentence naming a version."""
    found = []
    for index, (number, entry) in enumerate(_entries(section)):
        for position, sentence in enumerate(_SENTENCE.split(entry)):
            version = _VERSION.search(sentence)
            if not version or _FUTURE.search(sentence):
                continue
            found.append((index, number, position == 0, tuple(int(part) for part in version.groups()), sentence.strip()))
    return found


def _entries(section):
    entries = []
    for line in section.split("\n"):
        item = _ITEM.match(line)
        if item:
            number = re.match(r"\d+", line)
            entries.append([number.group(0) if number else None, _ITEM.sub("", line).strip()])
        elif line.strip() and entries and line[0].isspace():
            entries[-1][1] += " " + line.strip()  # wrapped list item
        elif line.strip():
            break  # text after the list, such as an admonition
    return [tuple(entry) for entry in entries]


def _relink(text, uri, page):
    """Rewrite links relative to the API page `uri` so they work from the generated page."""
    def fix(match):
        target = match.group(2)
        if re.match(r"[a-z]+:|#|/", target):
            return match.group(0)
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(uri), target))
        return match.group(1) + posixpath.relpath(resolved, posixpath.dirname(page)) + match.group(3)
    return _LINK.sub(fix, text)


def _link(title, uri, page):
    return f"[`{title}`]({posixpath.relpath(uri, posixpath.dirname(page))})"


def _added(pages, page):
    """Group the added pages by class: `basic_json`: [`get`](..), ...; pages without a class come first."""
    groups, single = {}, []
    for title, uri in pages:
        directory = posixpath.dirname(uri)
        if directory == "api":
            single.append(_link(title, uri, page))
        elif posixpath.basename(uri) == "index.md":
            groups.setdefault(directory, []).insert(0, f"[(overview)]({posixpath.relpath(uri, posixpath.dirname(page))})")
        else:
            groups.setdefault(directory, []).append(_link(title.split("::")[-1], uri, page))
    lines = [f"- {item}" for item in single]
    for directory, items in groups.items():
        lines.append(f"- `{posixpath.basename(directory)}`: " + ", ".join(items))
    return lines


def _render(page, entries):
    lines = []
    for version, bucket in entries:
        if len(entries) > 1:
            lines += [f"### Version {'.'.join(map(str, version))}", ""]
        if bucket["added"]:
            lines += [f"**Added ({len(bucket['added'])} pages):**", ""] + _added(bucket["added"], page) + [""]
        if bucket["changed"]:
            lines += ["**Changed:**", ""]
            lines += [f"- {_link(t, u, page)}: {_relink(x, u, page)}" for t, u, x in bucket["changed"]] + [""]
    return "\n".join(lines) if lines else "No documented API changes."
