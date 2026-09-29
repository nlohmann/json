#!/usr/bin/env python
"""Check the "Added in version" entries of the macro pages against the git tags.

For every macro documented in docs/api/macros, find the first release tag whose amalgamated header mentions the macro
and compare it with the version the page's "Version history" names. A macro documented as added *before* it appears
in any release, or documented with a released version although no release contains it, is reported as a problem. A
macro that appears in the header *before* its documented version is only a note: many macros existed internally before
they were documented for users. The check is heuristic and meant to be run by hand, not in CI.

usage: python3 check_version_history.py   (from docs/mkdocs/docs, needs the git tags)
"""

import functools
import glob
import re
# the script only runs git with fixed arguments and without a shell
import subprocess  # nosec B404
import sys

HEADER_PATHS = ["single_include/nlohmann/json.hpp", "src/json.hpp"]  # older releases used src/json.hpp
VERSION_RE = re.compile(r"[Aa]dded in (?:version )?(\d+)\.(\d+)\.(\d+)")
NAMED_VERSION_RE = re.compile(r"[Aa]dded `([A-Z0-9_]+)` in (?:version )?(\d+)\.(\d+)\.(\d+)")


def release_tags():
    # fixed git command without a shell
    tags = subprocess.run(["git", "tag", "-l", "v*"], capture_output=True, text=True, check=True).stdout.split()  # nosec B603, B607
    versions = []
    for tag in tags:
        match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", tag)
        if match:
            versions.append((tuple(map(int, match.groups())), tag))
    return sorted(versions)


@functools.lru_cache(maxsize=None)
def header(tag):
    for path in HEADER_PATHS:
        # fixed git command without a shell; the tag names come from "git tag"
        result = subprocess.run(["git", "show", f"{tag}:{path}"], capture_output=True, text=True)  # nosec B603, B607
        if result.returncode == 0:
            return result.stdout
    return ""


def macros_and_versions(page):
    with open(page, encoding="utf-8") as content:
        text = content.read()
    match = re.search(r"^# (.+)$", text, re.MULTILINE) or re.search(r"<h1>(.*?)</h1>", text, re.DOTALL)
    title = re.sub(r"<[^>]+>|\s+", " ", match.group(1))
    macros = [x.strip() for x in re.split(r"[,/]", title) if x.strip()]
    history = text.split("## Version history", 1)[-1]
    entries = re.split(r"\n(?=\s*(?:\d+\.|-)\s)", history)
    specific = {}  # entries like "Added `JSON_HAS_CPP_23` in version 3.12.0."
    general = []
    for entry in entries:
        named = NAMED_VERSION_RE.search(entry)
        if named:
            specific[named.group(1)] = tuple(map(int, named.groups()[1:]))
            continue
        match = VERSION_RE.search(entry)
        if match:
            general.append(tuple(map(int, match.groups())))
    rest = [macro for macro in macros if macro not in specific]
    if len(general) == len(rest):  # numbered history: one entry per macro, in title order
        pairs = list(zip(rest, general))
    else:
        pairs = [(macro, general[0]) for macro in rest] if general else []
    return pairs + sorted(specific.items())


def main():
    tags = release_tags()
    latest = tags[-1][0]
    problems = notes = 0
    for page in sorted(glob.glob("api/macros/*.md")):
        if page.endswith("index.md"):
            continue
        for macro, documented in macros_and_versions(page):
            pattern = re.compile(rf"\b{re.escape(macro)}\b")
            first = next((version for version, tag in tags if pattern.search(header(tag))), None)
            fmt = ".".join
            if first is None:
                if documented <= latest:
                    problems += 1
                    print(f"{page}: {macro} is documented as added in {fmt(map(str, documented))}, "
                          f"but no release up to {fmt(map(str, latest))} contains it")
            elif documented < first:
                problems += 1
                print(f"{page}: {macro} is documented as added in {fmt(map(str, documented))}, "
                      f"but first appears in {fmt(map(str, first))}")
            elif documented > first:
                notes += 1
                print(f"{page}: note: {macro} is documented as added in {fmt(map(str, documented))}, "
                      f"but is mentioned in the header since {fmt(map(str, first))}")
    print(f"{problems} possible problem(s), {notes} note(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
