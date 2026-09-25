# API Checker Tools

Tooling to extract, validate, and track changes to the public API surface of nlohmann/json.

## Overview

These tools use libclang AST parsing to programmatically derive "the public API" from C++ semantics
(class templates, access specifiers, namespace scoping) — independently of documentation status. The
extracted surface is the source of truth for what is considered "public API." On top of this, the tools
verify that every public entity carries a documentation link and detect API changes between releases.
A per-release historical record lives in [`history/`](history/README.md), one file per tagged `v3.*`
release, so past API changes can be derived without re-running libclang against old git refs.

See [POLICY.md](POLICY.md) for the full definition of what counts as public API, what's excluded, how
breaking vs. feature changes are classified, and known limitations.

## Installation

Install dependencies:

```bash
pip install -r tools/api_checker/requirements.txt
```

Requires:
- Python 3.7+
- libclang 18.1.1 (installed via pip)
- clang++ or clang (system package, for include-path discovery only — does not need to
  version-match the pinned libclang wheel)

## Tools

### extract_api.py

Extract the public API surface by parsing C++ AST using libclang. Produces two different outputs for
two different consumers — see "Two outputs, one extraction pass" below for why.

**Usage:**
```bash
python3 tools/api_checker/extract_api.py \
  --header include/nlohmann/json.hpp \
  --include include \
  --output api_snapshot.json \
  --surface-output api_surface.json
```

**Options:**
- `--header PATH` — Header file to analyze (default: `include/nlohmann/json.hpp`)
- `--include PATH` — Include directory for parsing (default: `include`)
- `--output PATH` — Full snapshot output (location + doc status; default: `api_snapshot.json`)
- `--surface-output PATH` — Minimal surface output (identity only; omit to skip)
- `--extra-isystem PATH` — Extra `-isystem` include path (repeatable), in case system-include
  discovery via `clang++ -E -v` ever fails on a given runner image
- `--self-test` — Run self-tests and exit (validates ABI-tag stripping)

**How it works:**
Parses the header file using libclang with `PARSE_DETAILED_PROCESSING_RECORD`, discovers system
includes via `clang++ -E -x c++ -v /dev/null`, and walks the AST:

1. For each of the 6 public class templates (`basic_json`, `adl_serializer`, `byte_container_with_subtype`,
   `json_pointer`, `json_sax`, `ordered_map`): locate the `CLASS_TEMPLATE` cursor with `is_definition() == True`
   — never a `CLASS_DECL` implicit instantiation, which silently drops SFINAE-guarded overloads
2. Extract public members: `CXX_METHOD`, `CONSTRUCTOR`, `DESTRUCTOR`, `CONVERSION_FUNCTION`, `FUNCTION_TEMPLATE`
   (callable tier — strict `@sa` requirement), and `TYPE_ALIAS_DECL` (type tier — with STL-container exemptions)
3. Extract free functions in `nlohmann::` namespace (excluding `detail::` and `std::`)
4. Normalize away ABI inline-namespace (regex `::json_abi[a-z_]*_v\d+_\d+_\d+` → `::`)
5. Use overload-disambiguating identity keys built from raw source-text signature capture,
   ABI-tag-stripped — see "Identity keys" below

**Two outputs, one extraction pass:**
- `--output` (full snapshot): each entry carries `location` (file:line) and documentation status
  (`doc_url`, `has_sa`). Consumed by `check_docs.py`. **Not meant to be committed** — `location` shifts
  on any unrelated code edit and `doc_url` changes when doc pages move, so a diff of this file mixes real
  API changes with pure noise.
- `--surface-output` (minimal surface): each entry has only `scope`, `kind`, `name`, `identity_name`,
  `tier`, `signature`, and `pretty_signature` — nothing that can change without the API itself changing.
  **This is the file that gets committed** (`tools/api_checker/api_surface.json` for the current
  working tree, `tools/api_checker/history/<tag>.json` per released tag) and diffed by `diff_api.py`.

**Identity keys — three approaches were tried and rejected before arriving at the current one:**
1. `{scope, name, kind, params}` from `cursor.get_arguments()`: silently collided for any overload set
   differentiated only by constness, ref-qualifiers, or SFINAE constraints rather than parameter types —
   confirmed empirically: `basic_json`'s two zero-argument `get()` overloads (one `const`, one not) both
   produced `params=[]` and silently overwrote each other. A full scan found **59 such silent overwrites
   across 27 colliding names**.
2. libclang's USR: correctly disambiguates every overload (it encodes the full mangled signature) — but
   *also* encodes the enclosing class template's own arity into every member's USR. Confirmed
   empirically against real release tags: `basic_json` gaining one new defaulted template parameter
   between v3.11.2 and v3.11.3 (a backward-compatible change) changed literally every member's USR,
   which made `diff_api.py` report **228 of 330 entries as "changed"** for a release with zero real
   breaking changes among them.
3. **Current approach**: raw source-text signature capture — `identity = (scope, identity_name, kind,
   signature)`, where `signature` is the declaration's own text (return type, name, parameter list,
   trailing cv/ref/noexcept qualifiers; comments and constructors' member-initializer-lists stripped;
   stops before the function body) read directly via the cursor's byte-offset extent. This is what's
   actually written in source — declared names like `ValueType`, never a resolved
   `basic_json<T0,...,T10>` — so it's immune to the class-arity problem above. Verified by manually
   cross-referencing every "added"/"removed"/"changed" entry in three real release-to-release diffs
   (v3.11.2→v3.11.3, v3.11.3→v3.12.0, v3.12.0→HEAD) against the actual `git diff` of the source — every
   one confirmed genuine. Full details, including several further edge-case fixes found the same way
   (a libclang tokenizer gap, comment-stripping, constructor-name arity-poisoning), are in
   `extract_api.py`'s `identity_key()`/`get_signature_text()` docstrings.

**Output (full snapshot, from `--output`):**
```json
{
  "meta": {
    "extracted_from": "include/nlohmann/json.hpp"
  },
  "public_api": {
    "<opaque internal key, not meant to be read>": {
      "scope": "nlohmann::basic_json",
      "name": "parse",
      "identity_name": "parse",
      "kind": "CXX_METHOD",
      "tier": "callable",
      "signature": "static basic_json parse ( InputType && i , ... )",
      "location": "include/nlohmann/json.hpp:4104",
      "doc_url": "https://json.nlohmann.me/api/basic_json/parse/",
      "has_sa": true,
      "pretty_signature": "nlohmann::basic_json::parse"
    }
  },
  "documented_non_public": []
}
```

`documented_non_public` lists entities **not** part of the public surface (private/protected members of
the six tracked classes) that surprisingly carry a real `@sa` URL — a genuine documentation leak. It does
not list public entries that merely lack `@sa`; that's `check_docs.py`'s job.

**Output (surface, from `--surface-output`):**
```json
{
  "format_version": 1,
  "meta": {
    "extracted_from": "include/nlohmann/json.hpp"
  },
  "public_api": [
    {
      "scope": "nlohmann::basic_json",
      "kind": "CXX_METHOD",
      "name": "parse",
      "identity_name": "parse",
      "tier": "callable",
      "signature": "static basic_json parse ( InputType && i , parser_callback_t cb = nullptr , const bool allow_exceptions = true , const bool ignore_comments = false )",
      "pretty_signature": "nlohmann::basic_json::parse"
    }
  ]
}
```

A flat, sorted list of self-describing records — `signature`/`identity_name` are the same values
`identity_key()` joins into one opaque internal string, exposed here as explicit fields so the file is
readable and diffable by inspection, not just by tooling. `identity_name` differs from `name` only for
constructors/destructors (a canonical `"(constructor)"`/`"(destructor)"` placeholder — see
`get_identity_name()`'s docstring for why `cursor.spelling` isn't used directly there).

`format_version` guards against a future change to this schema or to the identity-computing algorithm
silently corrupting a comparison against an older stored surface — bump it whenever such a change could
alter `signature`/`identity_name` text for otherwise-unchanged source (see `diff_api.py`).

### check_docs.py

Verify that all public API entries have valid documentation links and that no non-public entities
carry `@sa` comments.

**Usage:**
```bash
python3 tools/api_checker/check_docs.py --snapshot api_snapshot.json
```

**Options:**
- `--snapshot PATH` — Full API snapshot JSON file from `extract_api.py --output` (default: `api_snapshot.json`)

**How it works:**
Two-pass validation over the extracted snapshot:

1. For every `public_api` entry (callable tier, and type tier minus STL exemptions): flag if missing `@sa`,
   flag if `@sa` URL doesn't resolve to an existing documentation file (following `docs/mkdocs/mkdocs.yml`'s
   `redirect_maps` when a page has moved, and trying the class-overview conventions used by different
   classes — flat `<class>.md`, nested `<class>/<class>.md`, nested `<class>/index.md`)
2. For every `documented_non_public` entry: flag as unexpected `@sa` on a non-public entity

**Output:**
Prints warnings for each issue, categorized by rule:
- `docs/missing_sa_comment` — public API without `@sa` documentation link
- `docs/missing_doc_file` — `@sa` URL points to non-existent `.md` file
- `docs/invalid_sa_url` — malformed `@sa` URL
- `docs/sa_on_non_public` — unexpected `@sa` on a non-public entity

Exits with status 0 if all checks pass, 1 if issues found.

### diff_api.py

Compare the public API surface between two refs and classify changes as feature (added) or
breaking (removed / changed overload).

**Usage:**
```bash
python3 tools/api_checker/diff_api.py --old v3.12.0 --new HEAD
python3 tools/api_checker/diff_api.py --old v3.11.2 --new v3.11.3          # both resolved from history/
python3 tools/api_checker/diff_api.py --old v3.12.0 --new HEAD --fail-on-breaking
python3 tools/api_checker/diff_api.py --old-file a.json --new-file b.json  # compare two files directly
```

**Options:**
- `--old REF` / `--new REF` — Refs to compare (tags, branches, commits). `--new` defaults to `HEAD`.
  Each is resolved by checking `tools/api_checker/history/<ref>.json` first (fast — no libclang or
  git-archive needed), falling back to live extraction if no matching file exists there.
- `--old-file PATH` / `--new-file PATH` — Load an arbitrary surface JSON file directly, bypassing
  both git and `tools/api_checker/history/`. Mutually exclusive with `--old`/`--new` respectively.
- `--no-history` — Force live extraction even when a matching `tools/api_checker/history/<ref>.json`
  exists. Useful to check that a stored record is still faithful to a fresh run of the current tool.
- `--allow-format-mismatch` — Proceed even if the two surfaces have different `format_version`
  (otherwise `diff_api.py` refuses — see below).
- `--header PATH` / `--include PATH` — For live extraction only (default:
  `include/nlohmann/json.hpp` / `include`)
- `--fail-on-breaking` — Exit with status 1 if breaking changes are detected

**How it works:**
For a ref not found in `tools/api_checker/history/`, checks out the **full `include/` tree** at
that ref into a temp directory via `git archive` (a single-file checkout of `json.hpp` is not
enough — it `#include`s dozens of other headers that must exist at the same ref), then runs the
*current* `extract_api.py --surface-output` against it. Diffs the two surfaces by identity
(`scope`, `identity_name`, `kind`, `signature`):
- Identity only in the new surface → **feature**.
- Identity only in the old surface → **breaking** (removed).
- Same `(scope, name)` with a removed identity and an added identity → grouped as a **changed
  overload**, breaking by default. No automatic overload-compatibility reasoning is attempted — a
  human judges whether the change is actually source-compatible.

Before diffing, the two surfaces' `format_version` fields are compared; a mismatch aborts with an
error (override with `--allow-format-mismatch`) rather than silently producing an unsound diff — see
`extract_api.py`'s `SURFACE_FORMAT_VERSION` docstring for the incident that motivated this guard.

ABI-tag stripping is inherited automatically since both extractions go through the same
`extract_api.py`.

**Use case:** Run before cutting a release to verify the changelog correctly categorizes changes as
breaking vs. features.

### snapshot_release.py

Capture an immutable, per-release API surface record into `tools/api_checker/history/<tag>.json`.
This is what makes `diff_api.py` fast for released tags — see "How it works" above.

**Usage:**
```bash
python3 tools/api_checker/snapshot_release.py --ref v3.12.0
python3 tools/api_checker/snapshot_release.py --ref v3.11.0 --ref v3.12.0   # repeatable
python3 tools/api_checker/snapshot_release.py --all-tags                    # every v3.* tag
python3 tools/api_checker/snapshot_release.py --ref v3.12.0 --force         # overwrite an existing record
```

**Options:**
- `--ref REF` — Git tag to snapshot; repeatable
- `--all-tags` — Snapshot every `v3.*` tag (existing files are skipped unless `--force`)
- `--output-dir PATH` — Where to write (default: `tools/api_checker/history/`)
- `--force` — Overwrite an existing history file. History files are immutable by convention —
  only pass this for a deliberate, reviewed regeneration; review the resulting diff before
  committing
- `--header PATH` / `--include PATH` — Same as `diff_api.py`'s live-extraction options

**How it works:** Reuses `diff_api.py`'s `extract_surface_for_ref()` for the git-archive-and-extract
work, then adds `generated_at`/`generator` provenance and writes the result to
`tools/api_checker/history/<ref>.json`. Given multiple refs (or `--all-tags`), does **not** abort
the batch on one failing ref — collects failures and prints a summary at the end, so one
unparseable old tag doesn't block backfilling the releases that do work. See
`tools/api_checker/history/README.md` for the currently-known gaps (pre-restructuring tags that
predate the `include/nlohmann/` layout entirely).

**Not CI-automated** — this is a manual step in the release checklist (see below), by design.

### check_macros.py

Advisory-only cross-check between documented macros and their `#define`/reference sites. **Never blocks
CI**, regardless of findings.

**Usage:**
```bash
python3 tools/api_checker/check_macros.py
```

**Options:**
- `--macros-dir PATH` — Directory of macro doc pages (default: `docs/mkdocs/docs/api/macros`)
- `--include-dir PATH` — Directory to search for `#define`/reference sites (default: `include/nlohmann`)

**How it works:**
For each `.md` page under `docs/mkdocs/docs/api/macros/` (excluding `index.md`), extracts the macro
name(s) from the H1 heading — handling both plain single-macro headings and multi-line HTML headings
that list a family of related macros (e.g. the `NLOHMANN_DEFINE_DERIVED_TYPE_*` family) — then checks
whether each name is defined **or referenced** (`#define`, `#ifdef`, `#ifndef`, `defined(...)`) anywhere
under `include/nlohmann/`. Referenced-but-not-defined is deliberately accepted: macros like
`JSON_NOEXCEPTION` or `JSON_THROW_USER` are user-supplied overrides that the library only checks for,
never defines itself.

Only checks the documented-macro-still-exists direction (catches stale/renamed doc pages). Does **not**
check the converse (undocumented macros) — see [POLICY.md](POLICY.md)'s "Known limitations" for why.

## Continuous Integration

A GitHub Actions workflow (`.github/workflows/check_api_docs.yml`) runs on every pull request:

1. Installs `clang` (system package, for include discovery) and Python dependencies
2. Runs `extract_api.py`, regenerating both the ephemeral full snapshot and the tracked
   `tools/api_checker/api_surface.json`
3. Runs `check_docs.py` — **Phase 1: advisory** (`continue-on-error: true`), surfacing the doc backlog
   without failing the job while it's burned down. Will flip to blocking once the backlog is cleared.
4. Runs `check_macros.py` — always advisory
5. Diffs `tools/api_checker/api_surface.json` against the regenerated copy — **blocking from the start**
   (unlike the doc-backlog check, this is purely mechanical regeneration with no backlog to phase in,
   matching the precedent set by `check_amalgamation.yml`). Uploads a patch artifact if it differs, so
   contributors can `git apply` it instead of installing libclang locally.

## Workflow: Adding New Public API

1. Add the new public method/function to the header
2. Add a `/// @sa https://json.nlohmann.me/api/<class>/<member>/` comment above it
3. Create the corresponding documentation page at `docs/mkdocs/docs/api/<class>/<member>.md` and a
   `mkdocs.yml` nav entry
4. Regenerate and commit the tracked surface file:
   ```bash
   python3 tools/api_checker/extract_api.py --surface-output tools/api_checker/api_surface.json
   git add tools/api_checker/api_surface.json
   ```
5. Push your PR — CI verifies both the doc link and that the surface file is up to date

## Workflow: Release Checklist

Before cutting a release:

```bash
# Diff current API against the previous release
python3 tools/api_checker/diff_api.py --old v3.12.0 --new HEAD

# Review the output to verify the changelog correctly categorizes breaking vs. feature changes
```

After tagging the release:

```bash
# Capture and commit the new tag's API surface, so future diffs against it hit the fast,
# stored-file path instead of live-extracting every time. A manual step, not CI-automated.
python3 tools/api_checker/snapshot_release.py --ref v3.13.0
git add tools/api_checker/history/v3.13.0.json
```

## Troubleshooting

**libclang not found:**
```
Error: Could not locate libclang library
```
→ Ensure libclang is installed: `python3 -m pip install libclang==18.1.1`

**Parse errors in header:**
```
Parse errors encountered:
  ... list of diagnostics ...
```
→ Check that system includes can be discovered. Run `clang++ -E -x c++ -v /dev/null` and verify
the output includes a section titled `#include <...> search starts here:` with system paths.
If include discovery fails, use `--extra-isystem PATH` to provide additional paths.

**No API entries extracted (or very few):**
- Check that the header file exists and is valid C++: `ls -la include/nlohmann/json.hpp`
- Verify that no parse errors occur above
- Confirm that you're targeting a `CLASS_TEMPLATE` definition, not an implicit instantiation
  (the tool logs `Found N public API entries` — a zero or very small count suggests the wrong cursor kind)

**Doc link returns 404:**
- Verify the file exists at the expected path: `docs/mkdocs/docs/api/<class>/<member>.md`
- Check for URL encoding issues (e.g., `operator[]` → `operator%5B%5D`)
- Verify the URL structure in the `@sa` comment: should be `https://json.nlohmann.me/api/<path>/`
- Check `docs/mkdocs/mkdocs.yml`'s `redirect_maps` if the page has moved

**`tools/api_checker/api_surface.json` is out of date in CI:**
→ Regenerate and commit it: `python3 tools/api_checker/extract_api.py --surface-output tools/api_checker/api_surface.json`

**`diff_api.py` refuses with "format_version mismatch":**
→ One side is a stored surface (live `api_surface.json` or a `tools/api_checker/history/*.json`
file) captured with an older/newer version of `extract_api.py`'s identity-computing algorithm than
the other side. Comparing them directly could produce an unsound diff (this is exactly the failure
mode that motivated adding the check — see `extract_api.py`'s `SURFACE_FORMAT_VERSION` docstring).
Either regenerate the older side with the current tool, or pass `--allow-format-mismatch` if you
understand the risk and want to proceed anyway.

## Contributing

Report bugs or suggest improvements to [Discussion #3691](https://github.com/nlohmann/json/discussions/3691).
Read [POLICY.md](POLICY.md) first for the definition of public API this tooling enforces.
