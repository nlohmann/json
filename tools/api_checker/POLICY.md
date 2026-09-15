# Public API Policy

This document defines what counts as the **public API** of nlohmann/json for the purposes of the
`tools/api_checker/` tooling, what stability is (and is not) guaranteed, and how API changes are
classified as breaking or feature additions. It exists so that "public API" is a checkable, mechanical
property of the source, not a matter of convention or memory — see
[Discussion #3691](https://github.com/nlohmann/json/discussions/3691) for the original motivation.

## What counts as public API

The public API surface is derived from C++ semantics (class templates, access specifiers, namespace
scoping) by `extract_api.py`, not from the presence of documentation. It consists of:

1. **Public members of six class templates**: `basic_json`, `adl_serializer`,
   `byte_container_with_subtype`, `json_pointer`, `json_sax`, `ordered_map`. Specifically, the *primary
   template definition* (`CLASS_TEMPLATE` cursor with `is_definition() == True`) — never an implicit
   instantiation, which silently drops SFINAE-guarded overloads. Two tiers apply:
   - **Callable tier** (methods, constructors, destructors, conversion operators, function templates):
     every public callable requires its own `@sa` documentation link, without exception.
   - **Type tier** (public type aliases): requires `@sa`, except for a fixed exemption list of
     STL-container named-requirement aliases that mirror standard-library conventions rather than being
     independently documented: `value_type`, `reference`, `const_reference`, `pointer`, `const_pointer`,
     `iterator`, `const_iterator`, `reverse_iterator`, `const_reverse_iterator`, `difference_type`,
     `size_type`, `allocator_type`, `key_type`, `mapped_type`. This list is defined once, in
     `extract_api.py`'s `stl_exempt` set, and referenced here rather than duplicated.
2. **Free functions and operators in `nlohmann::`**, including `nlohmann::literals::json_literals`
   (the `operator""_json` / `operator""_json_pointer` user-defined literals). Comparison and stream
   operators on `basic_json` and `json_pointer`, `operator/`, `swap`.
3. **The six alias-exposed exception types**: `basic_json::exception`, `parse_error`,
   `invalid_iterator`, `type_error`, `out_of_range`, `other_error`. These are public `TYPE_ALIAS_DECL`s
   in `basic_json` (e.g. `using exception = detail::exception;`) whose underlying class is physically
   defined in `nlohmann::detail::exceptions.hpp`. `extract_api.py` follows the alias to find the `@sa` on
   the underlying `detail::` class definition, since that's where the existing documentation convention
   places it. Each exception class is documented as *one page* — its individual members (`what()`, `id`)
   are not separately tracked, matching the existing one-page-per-class convention.
4. **Macros**, governed separately by `docs/mkdocs/docs/api/macros/` (the curated list of ~30 pages is
   authoritative) and cross-checked, advisory-only, by `check_macros.py`. See "Known limitations" below
   for why macros can't be checked the same way as everything else.

## What's excluded

- **Everything in `nlohmann::detail::`**, with the one narrow exception above (exception-type aliases).
  **No stability is guaranteed for any symbol in the `detail::` namespace — clients must not rely on it**,
  regardless of whether a given `detail::` symbol happens to be reachable from user code today. This is
  an explicit, deliberate policy, not an oversight.
- **Private and protected members**, even of the six tracked classes. `extract_api.py` walks non-public
  members only to check they don't carry a stray `@sa` (a documentation leak) — never to add them to the
  public surface.
- **The ABI inline-namespace segment** (`json_abi_v3_12_0`, `json_abi_diag_v3_12_0`, etc. — see
  [docs/mkdocs/docs/features/namespace.md](../../docs/mkdocs/docs/features/namespace.md)). This is a
  version-tag identity concern for `diff_api.py` (it must not make every release look like the entire API
  was removed and re-added), not a scoping or visibility concern — the symbols inside it are public or
  not independent of the tag.

## Breaking vs. feature classification

`diff_api.py` compares the `public_api` surface of two snapshots using an overload-disambiguating
identity — `(scope, identity_name, kind, signature)`, where `signature` is the declaration's own
source text (return type, name, parameter list, trailing qualifiers; comments and constructors'
member-initializer-lists stripped). This is the third identity scheme this tooling has used; the
first two were each found broken by testing against real release tags, not by inspection — see
`extract_api.py`'s `identity_key()` docstring for the full history (a naive params-only key silently
collided on overloads differing only by constness/SFINAE; libclang's USR fixed that but encoded the
*enclosing class template's own arity*, so a single backward-compatible template-parameter addition
made ~228 of 330 `basic_json` entries look "changed" between two real releases with zero actual
breaking changes among them).

- An identity present only in the **new** snapshot → **feature** (addition).
- An identity present only in the **old** snapshot → **breaking** (removal).
- The same `(scope, name)` with one identity removed and a different one added → reported as a
  **changed overload**, classified breaking by default. No automatic overload-compatibility reasoning
  is attempted — whether a signature change is source-compatible is a judgment call for a human
  reviewer, not a sound problem for a CI tool to solve unsupervised.

## Stable per-release API history

`tools/api_checker/history/<tag>.json` holds one immutable, committed API-surface record per
released `v3.*` tag (captured via `snapshot_release.py`; see `tools/api_checker/README.md` and
`tools/api_checker/history/README.md`). `diff_api.py` reads from here automatically when a ref
matches a stored file, instead of live-extracting via `git archive` every time.

Every surface file (the live `api_surface.json` and every `history/*.json` record) carries a
`format_version` integer. **Bump it whenever a change to the schema, or to the identity-computing
algorithm (`get_signature_text()`/`get_identity_name()`/`identity_key()` in `extract_api.py`), could
alter the `signature` or `identity_name` text for otherwise-unchanged source.** `diff_api.py` refuses
by default to compare two surfaces with different `format_version` values — this is a direct,
mechanical safeguard against the exact class of bug that motivated the current identity scheme (see
above): a silent algorithm change corrupting every historical comparison with no way to detect it.
An explicit `--allow-format-mismatch` flag exists for a deliberate, informed comparison anyway.

Practical implication for anyone changing `extract_api.py`'s identity logic: bump
`SURFACE_FORMAT_VERSION`, and treat every already-committed `history/*.json` file as needing a
`--force` regeneration (reviewed, not blind) before it can be meaningfully compared against surfaces
produced by the new algorithm version.

## Stability guarantees

This tooling makes the project's existing commitments *mechanically checkable* — it does not introduce a
new promise:

- `ChangeLog.md` states the project "adheres to [Semantic Versioning](http://semver.org/)."
- [docs/mkdocs/docs/home/releases.md](../../docs/mkdocs/docs/home/releases.md) marks every 3.x release "All
  changes are backward-compatible" (except 3.0.0 itself, a major bump with a migration guide).
- `tests/abi/` provides a complementary, narrower guarantee: ABI/link compatibility *within one ABI tag*.
  That is a binary-compatibility concern; this tooling's concern is source/API-level — a symbol can be
  ABI-stable and still be a source-breaking change (e.g. a removed overload), or vice versa.

## Known limitations

- **Macros have no C++ access-specifier concept**, so the public/private test that works for classes
  doesn't transfer. Only a minority of documented macro `#define`s have an attached `@sa`-style comment
  (the `#ifndef X / #define X value #endif` idiom has no natural comment-attachment point), and internal
  helper macros live in the same files as public configuration macros, so no path-based exclusion works
  either. `check_macros.py` therefore only checks one direction: that every documented macro still has a
  matching `#define` somewhere under `include/nlohmann/` (catches stale/renamed doc pages). It does
  **not** attempt to detect undocumented macros — no reliable signal exists for that direction with the
  current codebase conventions, and this tool doesn't pretend otherwise.
- **`diff_api.py` does not track exception specifications or template-parameter-only changes.** A
  function whose `noexcept` status changes, or whose template parameter list changes without altering
  its externally-visible identity, will not be flagged.
- **Known API-hygiene gap, surfaced by this tooling rather than fixed**:
  `basic_json::insert_iterator` (a `public` member per C++ access rules) is a helper used internally by
  `insert()`; its own source comment calls it "Helper for insertion of an iterator." It has no
  documentation page and is deliberately left undocumented rather than either speculatively documented or
  silently exempted — this is exactly the class of undocumented-and-probably-shouldn't-be-public symbol
  this tooling exists to surface, per the motivating discussion. A future PR may reclassify it as private
  as a (breaking, ABI-relevant) cleanup; that is out of scope here.
