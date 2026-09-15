#!/usr/bin/env python3
"""Advisory-only cross-check between documented macros and their #define sites.

Macros have no C++ access-specifier concept, so the AST-based public/private test that
extract_api.py uses for classes doesn't transfer -- see tools/api_checker/POLICY.md's "Known
limitations" section. This script only checks one direction: that every macro documented under
docs/mkdocs/docs/api/macros/ still has a matching #define somewhere under include/nlohmann/,
catching stale or renamed doc pages. It does NOT check the converse (undocumented macros) --
no reliable signal exists for that direction given this codebase's conventions.

Never blocks CI -- always exits 0, even when it reports findings.
"""

import argparse
import glob
import os
import re
import sys

MACRO_TOKEN_RE = re.compile(r'\b([A-Z][A-Z0-9_]*)\b')

warnings = 0


def report(location: str, description: str):
    global warnings
    warnings += 1
    print(f'{warnings:3}. {location}:  {description}')


def extract_macro_names(md_path: str) -> list:
    """Extract macro name(s) from a doc page's H1 heading.

    Most pages use a single-line markdown heading ('# JSON_ASSERT'). A few document a family of
    related macros under one page using a multi-line HTML heading listing comma-separated names
    (e.g. NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE, ..._WITH_DEFAULT, ..._ONLY_SERIALIZE). Handle
    both: collect the heading text (markdown '# ...' line, or everything between <h1> and </h1>,
    which may span multiple lines), then split on commas.
    """
    with open(md_path) as f:
        content = f.read()

    heading_text = None
    html_match = re.search(r'<h1>(.*?)</h1>', content, re.DOTALL)
    if html_match:
        heading_text = html_match.group(1)
    else:
        for line in content.splitlines():
            if line.startswith('# '):
                heading_text = line[2:]
                break

    if not heading_text:
        return []

    names = []
    for part in heading_text.split(','):
        match = MACRO_TOKEN_RE.search(part)
        if match:
            names.append(match.group(1))
    return names


def macro_is_referenced(macro_name: str, include_dir: str) -> bool:
    """Check whether macro_name is defined OR referenced (#ifdef/#ifndef/defined()) anywhere
    under include_dir.

    Some documented macros (e.g. JSON_NOEXCEPTION, JSON_THROW_USER) are user-supplied overrides:
    the library only checks whether they're defined, it never #defines them itself. Requiring a
    literal #define would make this advisory check permanently noisy for that whole category, so
    presence of any reference is treated as "this macro still exists in the codebase."
    """
    pattern = re.compile(
        r'#\s*define\s+' + re.escape(macro_name) + r'\b'
        r'|#\s*ifn?def\s+' + re.escape(macro_name) + r'\b'
        r'|defined\s*\(\s*' + re.escape(macro_name) + r'\s*\)'
        r'|defined\s+' + re.escape(macro_name) + r'\b'
    )
    for root, _dirs, files in os.walk(include_dir):
        for fname in files:
            if not fname.endswith('.hpp'):
                continue
            path = os.path.join(root, fname)
            with open(path, encoding='utf-8', errors='ignore') as f:
                if pattern.search(f.read()):
                    return True
    return False


def check_macros(macros_dir: str, include_dir: str) -> bool:
    md_files = sorted(glob.glob(os.path.join(macros_dir, '*.md')))
    md_files = [f for f in md_files if os.path.basename(f) != 'index.md']

    print(f"Checking {len(md_files)} documented macros against #define sites in {include_dir}...")
    print(120 * "-")

    for md_path in md_files:
        macro_names = extract_macro_names(md_path)
        if not macro_names:
            report(md_path, "could not extract macro name(s) from H1 heading")
            continue

        for macro_name in macro_names:
            if not macro_is_referenced(macro_name, include_dir):
                report(md_path, f'documented macro "{macro_name}" is not defined or referenced under {include_dir}')

    print(120 * "-")

    if warnings > 0:
        print(f"\nFound {warnings} stale/renamed macro doc pages (advisory only, not blocking)")
    else:
        print("\nAll documented macros have a matching #define ✓")

    return warnings == 0


def main():
    parser = argparse.ArgumentParser(description='Advisory cross-check of documented macros vs. #define sites')
    parser.add_argument('--macros-dir', default='docs/mkdocs/docs/api/macros',
                       help='Directory containing macro documentation pages')
    parser.add_argument('--include-dir', default='include/nlohmann',
                       help='Directory to search for #define sites')

    args = parser.parse_args()
    check_macros(args.macros_dir, args.include_dir)
    # Advisory only -- never fail CI regardless of findings.
    sys.exit(0)


if __name__ == '__main__':
    main()
