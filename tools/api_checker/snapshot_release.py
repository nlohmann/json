#!/usr/bin/env python3
"""Capture immutable, per-release API surface records into tools/api_checker/history/.

These are the durable, committed counterpart to diff_api.py's live git-archive-and-extract path:
once a release is tagged, run this once to capture tools/api_checker/history/<tag>.json, commit
it, and future diffs against that tag hit the fast, no-libclang-needed stored-file path in
diff_api.py automatically. See tools/api_checker/README.md's "Workflow: Release Checklist" and
POLICY.md for the full policy (manual step, not CI-automated; files are immutable once committed
-- regenerate only via --force, and only as a deliberate, reviewed choice).
"""

import argparse
import datetime
import json
import os
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
HISTORY_DIR = os.path.join(SCRIPT_DIR, 'history')

sys.path.insert(0, SCRIPT_DIR)
from diff_api import extract_surface_for_ref  # noqa: E402


def discover_v3_tags() -> list:
    """List every v3.* git tag, sorted by dotted version (not lexicographically -- v3.9.0 must
    sort before v3.10.0)."""
    result = subprocess.run(['git', 'tag', '--list', 'v3.*'], capture_output=True, text=True, check=True)
    tags = [t for t in result.stdout.splitlines() if t.strip()]

    def version_key(tag):
        parts = tag.lstrip('v').replace('-', '.').split('.')
        return tuple(int(p) if p.isdigit() else p for p in parts)

    return sorted(tags, key=version_key)


def snapshot_one(ref: str, output_dir: str, force: bool, header: str, include: str) -> tuple:
    """Capture one ref's surface. Returns (ref, success, message)."""
    output_path = os.path.join(output_dir, f"{ref}.json")
    if os.path.exists(output_path) and not force:
        return ref, True, f"skipped (already exists at {output_path}; use --force to overwrite)"

    try:
        surface = extract_surface_for_ref(ref, header, include)
    except SystemExit:
        return ref, False, "extraction failed (see output above)"
    except Exception as e:  # noqa: BLE001 -- a batch backfill must not die on one bad tag
        return ref, False, f"unexpected error: {e}"

    surface['meta']['generated_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    surface['meta']['generator'] = 'tools/api_checker/extract_api.py'

    os.makedirs(output_dir, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(surface, f, indent=2, sort_keys=True)
        f.write('\n')

    return ref, True, f"{len(surface['public_api'])} entries -> {output_path}"


def main():
    parser = argparse.ArgumentParser(
        description='Capture per-release API surface snapshots into tools/api_checker/history/')
    parser.add_argument('--ref', action='append', default=[],
                       help='Git ref (tag) to snapshot; repeatable')
    parser.add_argument('--all-tags', action='store_true',
                       help='Snapshot every v3.* tag (existing history files are skipped unless --force)')
    parser.add_argument('--output-dir', default=HISTORY_DIR,
                       help='Directory to write history files into (default: tools/api_checker/history/)')
    parser.add_argument('--force', action='store_true',
                       help='Overwrite an existing history file (history files are immutable by '
                       'convention -- only pass this for a deliberate, reviewed regeneration)')
    parser.add_argument('--header', default='include/nlohmann/json.hpp')
    parser.add_argument('--include', default='include')

    args = parser.parse_args()

    refs = list(args.ref)
    if args.all_tags:
        refs = discover_v3_tags()

    if not refs:
        parser.error('specify at least one --ref, or --all-tags')

    print(f"Snapshotting {len(refs)} ref(s)...")
    results = []
    for ref in refs:
        print(f"\n=== {ref} ===")
        result = snapshot_one(ref, args.output_dir, args.force, args.header, args.include)
        print(result[2])
        results.append(result)

    failures = [(ref, msg) for ref, ok, msg in results if not ok]
    print("\n" + "=" * 70)
    print(f"Done: {len(results) - len(failures)} succeeded, {len(failures)} failed")
    if failures:
        print("\nFailures (review and record accepted gaps in tools/api_checker/history/README.md):")
        for ref, msg in failures:
            print(f"  {ref}: {msg}")
        sys.exit(1)


if __name__ == '__main__':
    main()
