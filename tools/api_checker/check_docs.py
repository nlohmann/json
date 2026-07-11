#!/usr/bin/env python3
"""Verify that public API entries have documentation links.

Consumes an API snapshot from extract_api.py and checks:
1. Every public callable/type-tier entry has an @sa comment (with exceptions)
2. Every @sa URL resolves to an existing documentation file
3. No @sa comments appear on non-public entities
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

warnings = 0

# STL-container-named-requirement aliases that are exempt from @sa requirement
STL_EXEMPT = {'value_type', 'reference', 'const_reference', 'pointer', 'const_pointer',
              'iterator', 'const_iterator', 'reverse_iterator', 'const_reverse_iterator',
              'difference_type', 'size_type', 'allocator_type', 'key_type', 'mapped_type'}


def get_repo_root():
    """Find the repository root via git, so this script works regardless of invoking CWD."""
    try:
        result = subprocess.run(
            ['git', 'rev-parse', '--show-toplevel'],
            capture_output=True, text=True, check=True, timeout=10
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return os.getcwd()


REPO_ROOT = get_repo_root()
MKDOCS_YML = os.path.join(REPO_ROOT, 'docs', 'mkdocs', 'mkdocs.yml')


def load_redirect_map() -> dict:
    """Parse the redirect_maps block of docs/mkdocs/mkdocs.yml: {old_relative_path: new_relative_path}.

    mkdocs' redirect plugin lets a doc page move without breaking existing @sa URLs -- e.g.
    'api/basic_json/operator_ltlt.md' redirects to the real file at 'api/operator_ltlt.md'.
    Without consulting this map, url_to_docfile() would flag every redirected URL as a broken link.
    """
    if not os.path.exists(MKDOCS_YML):
        return {}
    with open(MKDOCS_YML) as f:
        content = f.read()
    redirect_map = {}
    for m in re.finditer(r"^\s*'([^']+\.md)':\s*(\S+\.md)\s*$", content, re.MULTILINE):
        redirect_map[m.group(1)] = m.group(2)
    return redirect_map


REDIRECT_MAP = load_redirect_map()


def report(rule: str, location: str, description: str):
    """Report a documentation issue."""
    global warnings
    warnings += 1
    print(f'{warnings:3}. {location}:  {description} [{rule}]')


def url_to_docfile(url: str) -> str | None:
    """Convert @sa URL to the documentation file it resolves to, following mkdocs redirects."""
    if not url:
        return None

    # Extract path after /api/
    match = re.search(r'/api/(.+?)/?$', url)
    if not match:
        return None

    # URL-decode each path component
    path_parts = [unquote(part) for part in match.group(1).split('/')]
    relative_path = 'api/' + '/'.join(path_parts) + '.md'

    docs_root = os.path.join(REPO_ROOT, 'docs', 'mkdocs', 'docs')
    direct_path = os.path.join(docs_root, relative_path)

    # Class-overview URLs (a single path segment after /api/, e.g. ".../api/json_pointer/")
    # use inconsistent on-disk conventions across classes: ordered_map.md is a flat file,
    # byte_container_with_subtype/byte_container_with_subtype.md nests under a same-named
    # file, json_pointer/index.md nests under index.md. Try all observed conventions.
    candidates = [direct_path]
    if len(path_parts) == 1:
        stem = path_parts[0]
        candidates.append(os.path.join(docs_root, 'api', stem, 'index.md'))
        candidates.append(os.path.join(docs_root, 'api', stem, stem + '.md'))

    redirected = REDIRECT_MAP.get(relative_path)
    if redirected:
        candidates.append(os.path.join(docs_root, redirected))

    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate

    # Nothing resolved -- return the direct path so the caller reports a meaningful "missing" location.
    return direct_path


def check_docs(snapshot_path: str):
    """Check documentation for all API entries."""
    if not os.path.exists(snapshot_path):
        print(f"Error: Snapshot file not found: {snapshot_path}")
        sys.exit(1)

    with open(snapshot_path, 'r') as f:
        data = json.load(f)

    api = data.get('public_api', {})
    documented_non_public = data.get('documented_non_public', [])

    print(f"Checking documentation for {len(api)} API entries...")
    print(120 * "-")

    # Check public API entries
    for identity_key, entry in sorted(api.items()):
        location = entry.get('location', 'unknown')
        name = entry.get('name', '?')
        tier = entry.get('tier', '?')
        doc_url = entry.get('doc_url')
        has_sa = entry.get('has_sa', False)

        # Skip type_exempt tier entries
        if tier == 'type_exempt':
            continue

        # Check for missing @sa
        if not has_sa:
            report('docs/missing_sa_comment', location,
                  f'public API "{name}" (tier: {tier}) has no @sa documentation link')
            continue

        # Verify URL resolves to an existing file
        doc_file = url_to_docfile(doc_url)
        if not doc_file:
            report('docs/invalid_sa_url', location,
                  f'public API "{name}" has invalid @sa URL: {doc_url}')
            continue

        if not os.path.exists(doc_file):
            display_path = os.path.relpath(doc_file, REPO_ROOT)
            report('docs/missing_doc_file', location,
                  f'public API "{name}" @sa URL points to non-existent file: {display_path}')

    # Check documented_non_public entries
    for entry in documented_non_public:
        location = entry.get('location', 'unknown')
        reason = entry.get('reason', '?')
        report('docs/sa_on_non_public', location,
              f'@sa comment found on non-public entity: {reason}')

    print(120 * "-")

    if warnings > 0:
        print(f"\nFound {warnings} documentation issues")
        return False
    else:
        print("\nAll public API entries are properly documented ✓")
        return True


def main():
    parser = argparse.ArgumentParser(description='Check documentation for public API')
    parser.add_argument('--snapshot', default='api_snapshot.json',
                       help='Path to API snapshot JSON file')

    args = parser.parse_args()

    if not check_docs(args.snapshot):
        sys.exit(1)


if __name__ == '__main__':
    main()
