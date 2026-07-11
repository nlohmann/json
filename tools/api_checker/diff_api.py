#!/usr/bin/env python3
"""Diff the public API surface between two refs to flag breaking vs. feature changes.

A "ref" for --old/--new is resolved in this order:
1. A stored, committed historical record at tools/api_checker/history/<ref>.json, if one exists
   and --no-history wasn't passed (fast path -- no libclang/git-archive needed).
2. Live extraction: check the ref out via `git archive` into a temp dir and run extract_api.py
   against it (needed for HEAD, branches, or any tag not yet backfilled into history/).
--old-file/--new-file bypass both and load an arbitrary surface JSON file directly.

Uses extract_api.py's --surface-output (identity-only: scope, kind, name, identity_name, tier,
signature, pretty_signature -- no location, no doc_url) for both sides, so the diff reflects only
genuine API changes, never unrelated code motion or documentation-site restructuring. Identity is
(scope, identity_name, kind, signature) -- see extract_api.py's identity_key()/get_signature_text()
docstrings for the full history of why this is what it is: a naive {scope,name,kind,params} key
silently collided on overloads differing only by constness/SFINAE; switching to libclang's USR
fixed that but encoded the *enclosing class template's own arity* into every member's identity, so
a single backward-compatible template-parameter addition (confirmed via real release tags
v3.11.2->v3.11.3) made ~228 of 330 entries look "changed" for a release with no real breaking
changes. The current raw-source-text-signature approach was arrived at, and each of several further
refinements verified, by testing against real historical releases -- not by inspecting code alone.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from collections import defaultdict

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
HISTORY_DIR = os.path.join(SCRIPT_DIR, 'history')

# The format_version this build of diff_api.py understands. Kept in sync with
# extract_api.py's SURFACE_FORMAT_VERSION by convention (both bump together whenever the
# identity-computing algorithm changes) -- imported directly so there's exactly one source of
# truth, not two constants that can drift apart.
sys.path.insert(0, SCRIPT_DIR)
from extract_api import SURFACE_FORMAT_VERSION  # noqa: E402


def resolve_commit_sha(ref: str) -> str | None:
    """Resolve a ref to its full commit sha, or None if that fails."""
    try:
        result = subprocess.run(
            ['git', 'rev-parse', ref],
            capture_output=True, text=True, check=True, timeout=10
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return None


def extract_surface_for_ref(ref: str, header: str = 'include/nlohmann/json.hpp',
                            include: str = 'include') -> dict:
    """Check out the full include/ tree at `ref` into a temp dir and extract its API surface.

    A single-file checkout of json.hpp is not enough: json.hpp #includes dozens of other
    headers under nlohmann/detail/ that must exist at the same ref for parsing to succeed.

    Returns the full loaded surface JSON (format_version, meta, public_api list), with `ref` and
    the resolved commit sha recorded in meta -- callers that only care about the diff can ignore
    these; snapshot_release.py uses them as a historical record's provenance.
    """
    with tempfile.TemporaryDirectory(prefix='api_checker_') as tmpdir:
        archive = subprocess.run(
            ['git', 'archive', ref, '--', 'include'],
            capture_output=True, check=True
        )
        subprocess.run(['tar', '-x', '-C', tmpdir], input=archive.stdout, check=True)

        ref_include = os.path.join(tmpdir, include)
        ref_header = os.path.join(tmpdir, header)
        if not os.path.exists(ref_header):
            print(f"Error: {header} does not exist at ref {ref}")
            sys.exit(1)

        surface_output = os.path.join(tmpdir, 'surface.json')
        result = subprocess.run(
            [sys.executable, os.path.join(SCRIPT_DIR, 'extract_api.py'),
             '--header', ref_header,
             '--include', ref_include,
             '--output', os.path.join(tmpdir, 'snapshot.json'),
             '--surface-output', surface_output],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"Error extracting API at ref {ref}:")
            print(result.stdout)
            print(result.stderr)
            sys.exit(1)

        with open(surface_output) as f:
            surface = json.load(f)

    # extract_api.py resolved 'extracted_from' relative to *its own* invocation cwd/repo-root
    # detection, which inside this temp checkout is meaningless (a path like
    # "../../../../var/folders/.../tmp.XXXX/include/nlohmann/json.hpp") -- overwrite with the
    # stable, repo-relative header path actually passed in, so a stored history file's metadata
    # doesn't embed a throwaway temp directory name.
    surface.setdefault('meta', {})['extracted_from'] = header
    surface['meta']['ref'] = ref
    commit_sha = resolve_commit_sha(ref)
    if commit_sha:
        surface['meta']['commit'] = commit_sha
    return surface


def load_surface_file(path: str) -> dict:
    """Load a surface JSON file from disk (a stored history/ record or an explicit --old-file/--new-file)."""
    with open(path) as f:
        return json.load(f)


def resolve_surface(ref: str | None, explicit_file: str | None, header: str, include: str,
                    no_history: bool) -> tuple:
    """Resolve one side of a diff. Returns (surface_dict, description_string_for_display)."""
    if explicit_file:
        return load_surface_file(explicit_file), f"file:{explicit_file}"

    history_path = os.path.join(HISTORY_DIR, f"{ref}.json")
    if not no_history and os.path.exists(history_path):
        return load_surface_file(history_path), f"history:{ref}"

    return extract_surface_for_ref(ref, header, include), f"live:{ref}"


def build_identity_dict(public_api: list) -> dict:
    """Group a surface's public_api list by identity for diffing.

    Identity is (scope, identity_name, kind, signature) -- the same four components
    extract_api.py's identity_key() joins into one opaque string internally, exposed here as
    explicit fields on each record (see extract_api.py's write_surface()) so this reconstruction
    is a plain, visible tuple lookup rather than decoding anything.
    """
    return {
        (entry['scope'], entry['identity_name'], entry['kind'], entry['signature']): entry
        for entry in public_api
    }


def diff_surfaces(old_api: dict, new_api: dict) -> dict:
    """Compare two API surfaces by identity key, grouping same-(scope,name) changes."""
    old_keys = set(old_api.keys())
    new_keys = set(new_api.keys())

    added_keys = new_keys - old_keys
    removed_keys = old_keys - new_keys

    # Group removed/added entries by (scope, name) to detect "changed overload" pairs,
    # rather than reporting a same-named removal+addition as two unrelated changes.
    removed_by_name = defaultdict(list)
    for key in removed_keys:
        entry = old_api[key]
        removed_by_name[(entry['scope'], entry['name'])].append(key)

    added_by_name = defaultdict(list)
    for key in added_keys:
        entry = new_api[key]
        added_by_name[(entry['scope'], entry['name'])].append(key)

    changed = []
    pure_added = []
    pure_removed = []

    for name, removed_list in removed_by_name.items():
        if name in added_by_name:
            added_list = added_by_name.pop(name)
            for key in removed_list:
                changed.append({'scope': name[0], 'name': name[1],
                               'old': old_api[key]['pretty_signature'],
                               'new': new_api[added_list[0]]['pretty_signature']})
        else:
            for key in removed_list:
                pure_removed.append(old_api[key])

    for name, added_list in added_by_name.items():
        for key in added_list:
            pure_added.append(new_api[key])

    return {
        'added': sorted(pure_added, key=lambda e: e['pretty_signature']),
        'removed': sorted(pure_removed, key=lambda e: e['pretty_signature']),
        'changed': sorted(changed, key=lambda e: (e['scope'], e['name'])),
    }


def print_diff(diff: dict, old_desc: str, new_desc: str) -> bool:
    """Print a human-readable diff report. Returns True if breaking changes were found."""
    print(120 * "-")
    print(f"API Diff: {old_desc} -> {new_desc}")
    print(120 * "-")

    if diff['added']:
        print(f"\nAdded ({len(diff['added'])} entries) -- feature:")
        for entry in diff['added']:
            print(f"  + {entry['pretty_signature']}")

    if diff['removed']:
        print(f"\nRemoved ({len(diff['removed'])} entries) -- BREAKING:")
        for entry in diff['removed']:
            print(f"  - {entry['pretty_signature']}")

    if diff['changed']:
        print(f"\nChanged overloads ({len(diff['changed'])} entries) -- BREAKING by default:")
        for entry in diff['changed']:
            print(f"  ~ {entry['old']}  ->  {entry['new']}")

    if not any([diff['added'], diff['removed'], diff['changed']]):
        print("\nNo API changes detected")

    print(120 * "-")

    breaking = bool(diff['removed'] or diff['changed'])
    if breaking:
        print("\nWARNING: Potential BREAKING CHANGES detected:")
        print(f"  - {len(diff['removed'])} removed entries")
        print(f"  - {len(diff['changed'])} changed overloads")
    if diff['added']:
        print(f"\nNew features: {len(diff['added'])} added entries")

    return breaking


def main():
    parser = argparse.ArgumentParser(description='Diff public API surface between two refs')
    parser.add_argument('--old', help='Old git ref (tag/commit) -- checks tools/api_checker/history/ first, '
                       'then falls back to live extraction')
    parser.add_argument('--new', help='New git ref (default: HEAD unless --new-file is given)')
    parser.add_argument('--old-file', help='Path to a stored surface JSON file for the "old" side '
                       '(bypasses git and tools/api_checker/history/ entirely)')
    parser.add_argument('--new-file', help='Path to a stored surface JSON file for the "new" side '
                       '(bypasses git and tools/api_checker/history/ entirely)')
    parser.add_argument('--no-history', action='store_true',
                       help='Force live extraction even if a matching tools/api_checker/history/<ref>.json '
                       'exists -- useful to check a stored record is still faithful to a fresh run')
    parser.add_argument('--allow-format-mismatch', action='store_true',
                       help='Proceed even if the two surfaces have different format_version (results may '
                       'be unsound -- the identity algorithm may differ between versions)')
    parser.add_argument('--header', default='include/nlohmann/json.hpp',
                       help='Header file to analyze (relative to repo root, live-extraction only)')
    parser.add_argument('--include', default='include',
                       help='Include directory (relative to repo root, live-extraction only)')
    parser.add_argument('--fail-on-breaking', action='store_true',
                       help='Exit with status 1 if breaking changes are detected')

    args = parser.parse_args()

    if args.old and args.old_file:
        parser.error('--old and --old-file are mutually exclusive')
    if not args.old and not args.old_file:
        parser.error('one of --old or --old-file is required')
    if args.new and args.new_file:
        parser.error('--new and --new-file are mutually exclusive')

    new_ref = args.new or ('HEAD' if not args.new_file else None)

    print(f"Resolving old surface ({args.old_file or args.old})...")
    old_surface, old_desc = resolve_surface(args.old, args.old_file, args.header, args.include, args.no_history)

    print(f"Resolving new surface ({args.new_file or new_ref})...")
    new_surface, new_desc = resolve_surface(new_ref, args.new_file, args.header, args.include, args.no_history)

    old_fmt = old_surface.get('format_version')
    new_fmt = new_surface.get('format_version')
    # Check both surfaces against SURFACE_FORMAT_VERSION (what *this build* of diff_api.py
    # understands), not just against each other: two surfaces on the same format_version could
    # still both be on a version this build predates and doesn't correctly interpret.
    mismatched = old_fmt != SURFACE_FORMAT_VERSION or new_fmt != SURFACE_FORMAT_VERSION
    if mismatched and not args.allow_format_mismatch:
        print(f"Error: format_version mismatch. This build of diff_api.py understands "
              f"format_version {SURFACE_FORMAT_VERSION!r}, but {old_desc} is {old_fmt!r} and "
              f"{new_desc} is {new_fmt!r}.")
        print("The identity/signature algorithm may differ between these two surfaces, making a diff unsound.")
        print("Re-run with --allow-format-mismatch to proceed anyway.")
        sys.exit(1)
    elif mismatched:
        print(f"WARNING: proceeding with mismatched format_version (this build understands "
              f"{SURFACE_FORMAT_VERSION!r}; {old_desc}={old_fmt!r}, {new_desc}={new_fmt!r}) as requested.")

    old_api = build_identity_dict(old_surface['public_api'])
    new_api = build_identity_dict(new_surface['public_api'])

    print(f"\nComparing {len(old_api)} old entries with {len(new_api)} new entries...")
    diff = diff_surfaces(old_api, new_api)

    breaking = print_diff(diff, old_desc, new_desc)

    if args.fail_on_breaking and breaking:
        sys.exit(1)


if __name__ == '__main__':
    main()
