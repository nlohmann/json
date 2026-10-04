"""Mark version numbers newer than the latest release with an "unreleased" badge."""

# The documentation is published from the develop branch and already describes the next release ("Added in version
# 3.13.0."). Every "version X.Y.Z" newer than the version in include/nlohmann/detail/abi_macros.hpp (which is only
# bumped when a release is made) gets a badge, so readers of a released version can tell which features they do not
# have yet; after a release, the badges disappear. Fenced and inline code, headings (a badge would change their
# anchor), and admonition/tab titles are left untouched, and statements about the future ("will be removed in version
# 4.0.0") are skipped. copy_markdown_source.py copies the raw source, so the *.md copies are unaffected.

import logging
import os
import re

log = logging.getLogger("mkdocs.hooks.unreleased_versions")

_HEADER = os.path.join("..", "..", "include", "nlohmann", "detail", "abi_macros.hpp")  # relative to mkdocs.yml
_VERSION_MACRO = re.compile(r"^#define NLOHMANN_JSON_VERSION_(MAJOR|MINOR|PATCH) (\d+)", re.MULTILINE)
_MENTION = re.compile(r"\b[Vv]ersion\s+(\d+)\.(\d+)\.(\d+)\b")
_FUTURE = re.compile(r"\b(?:will|planned|ahead of|until)\b[^.;:!?]*$", re.IGNORECASE)
_FENCE = re.compile(r"^\s*(`{3,}|~{3,})")
_NO_BADGE = re.compile(r"^\s*(?:#{1,6}(?:\s|$)|<h[1-6][\s>]|(?:!!!|\?\?\?\+?|===)\s)")
_NEW_BLOCK = re.compile(r"^\s*(?:[-*+]|\d+\.)\s")
_INLINE_CODE = re.compile(r"(`+).+?\1")

_released = None
_badge = ""


def on_config(config):
    global _released, _badge
    path = os.path.join(os.path.dirname(config.config_file_path), _HEADER)
    try:
        with open(path, encoding="utf-8") as header:
            parts = dict(_VERSION_MACRO.findall(header.read()))
        _released = (int(parts["MAJOR"]), int(parts["MINOR"]), int(parts["PATCH"]))
    except (OSError, KeyError) as error:
        _released = None
        log.info(f"not marking unreleased versions: cannot read {path} ({error})")  # info: must not break --strict
        return
    version = ".".join(map(str, _released))
    _badge = (f' <span class="unreleased-version" title="Not part of a release yet; the latest release is '
              f'{version}.">unreleased</span>')


def on_page_markdown(markdown, *, page, config, files):
    if _released is None:
        return markdown
    lines, fence, context = [], None, ""
    for line in markdown.split("\n"):
        original = line
        match = _FENCE.match(line)
        if fence:
            if match and line.strip() == match.group(1) and match.group(1)[0] == fence[0] \
                    and len(match.group(1)) >= len(fence):
                fence = None
        elif match:
            fence = match.group(1)
        elif not _NO_BADGE.match(line):
            line = _mark_line(line, "" if _NEW_BLOCK.match(line) else context)
        lines.append(line)
        # the previous line catches statements like "will be removed in\nversion 4.0.0"
        context = original if original.strip() else ""
    return "\n".join(lines)


def _mark_line(line, context):
    result, position = [], 0
    for code in _INLINE_CODE.finditer(line):
        result.append(_mark_text(line[position:code.start()], context + " " + line[:position]))
        result.append(code.group(0))
        position = code.end()
    result.append(_mark_text(line[position:], context + " " + line[:position]))
    return "".join(result)


def _mark_text(text, before):
    def badge(match):
        version = tuple(int(part) for part in match.groups())
        if version <= _released or _FUTURE.search(before + text[:match.start()]):
            return match.group(0)
        return match.group(0) + _badge
    return _MENTION.sub(badge, text)
