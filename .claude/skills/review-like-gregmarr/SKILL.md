---
name: review-like-gregmarr
description: Review a diff, branch, or PR of nlohmann/json the way long-time contributor gregmarr does — a line-by-line read focused on C++11 correctness, reference invalidation, backward/source compatibility, ODR/ABI, duplicated logic, hidden costs, repo conventions (amalgamation, astyle, macros) and precise docs, phrased as short courteous questions. Use when asked to "review like Greg", "gregmarr review", or for a careful maintainer-style review of changes to this library.
---

# Review like gregmarr

Distilled from ~1,400 inline review comments and ~1,300 issue/PR comments by
@gregmarr on nlohmann/json. He is a careful, courteous, line-by-line reviewer
who ("just a contributor") defers final decisions to @nlohmann.

## Workflow

1. Determine the target: a PR number (`gh pr diff <n>`), a branch
   (`git diff $(git merge-base HEAD develop)...HEAD`), or the working tree
   (`git diff`). Read the full diff, and open surrounding code in `include/nlohmann/`
   whenever a hunk's context is not enough to judge it.
2. Walk the diff **file by file, hunk by hunk**, applying the checklist below.
   Comment on specific lines; don't write a big essay.
3. Write the review in his voice (see "Voice"). Group nothing artificially —
   emit one comment per location, in file/line order, with `path:line`.
4. If the same issue repeats, comment fully once, then "As above" /
   "Same here (and N other places in this file)."
5. End with a 1–3 line summary only if useful (e.g. "Just this remaining and
   then LGTM." or "@nlohmann thoughts on the naming?"). Don't post to GitHub
   unless the user asks.

## Checklist (roughly in order of how often he raises them)

### Duplication and simplification (most frequent)
- Copy-pasted bodies, duplicated `#if/#elif` blocks, or "a copy of this function
  that can get out of sync" → propose a shared helper or alias, with a code sketch.
- **Diverging limits/constants**: a new depth/recursion limit or magic number
  where one already exists → "Should this reuse the existing recursion limit?
  Different limits per operation invites them to diverge over time."
- Unneeded variables, parameters that can be deduced, values passed to a
  function that the constructor already has, output parameter == return value.
- Verbose type spellings → `using` alias / alias template; `decltype()` where the
  type is known.
- Disabling a lint warning instead of fixing the code ("why not just add the parens?").

### Lifetime, invalidation, UB
- A reference/pointer/iterator into a container (`stack.back()`,
  `container_stack.back()`, `ordered_map` elements) held across `push_back`,
  `pop_back`, `emplace`, or reallocation → "This invalidates `top`." Prefer a
  `const` copy, or at least a comment warning future editors.
- Dangling refs from rvalue arguments stored in adapters; views outliving documents.
- Wrong logic operators (`&&` vs `||`), lost `!`, unreachable code, `continue`
  that should be `break`, missing `return`, off-by-one in counters
  (`chars_read` incremented twice).
- Uninitialized members → default member initializers; parameters that
  "should not have a default so it's never left off by accident".
- Exception safety: leaks when `to_json` is called on a non-null value, partial
  state, destructors that allocate, swallowed exceptions (`noexcept` that hides
  throws — "The library shouldn't try to swallow the exception").
- Thread-unsafe calls (`setlocale`), specializations that redefine `std::` things
  (ODR / UB).
- Narrowing/truncation: `static_cast<std::make_unsigned<...>>`, signed/unsigned
  `char` cases, `n == 0` edge cases, buffer overruns guarded only by `JSON_ASSERT`.

### C++11 floor and portability
- The library requires only **C++11**: flag `if constexpr`, C++14 generic
  lambdas/variable templates, `std::clamp`, C++17 library features, etc. unless
  gated.
- Gate on the library's macros (`JSON_HAS_CPP_17`, `JSON_HAS_CPP_20`,
  `JSON_HAS_THREE_WAY_COMPARISON`, `JSON_HAS_FILESYSTEM`) or feature-test macros
  with `defined()` checks and exact values
  (`#if defined(__cpp_lib_char8_t) && __cpp_lib_char8_t >= 201811`), not raw
  `__cplusplus`. Don't silently disable a feature for an existing config.
- User-overridable macros: if externally defined, leave as-is — never clobber to
  `1` (breaks `#define X 0`). `#if X` vs `#ifdef X` must match the convention.
- New macros start with `JSON_` / `NLOHMANN_JSON_` consistently with neighbors.
- `throw` must be `JSON_THROW` (and `try/catch` → `JSON_TRY/JSON_CATCH`) so
  `JSON_NOEXCEPTION` builds work.
- `(std::min)(a, b)` / `(std::max)` for Windows macros; MSVC warnings (C4100
  etc.); `string_t` not being `std::string`/`char`.
- Code relying on operations not required of user-supplied `array_t`/`object_t`
  (range ctor, `emplace_hint`, allocator) → ask whether that's allowed.
- Does it work with `JSON_USE_IMPLICIT_CONVERSIONS=0`? With `JSON_DIAGNOSTICS`?

### Compatibility, ABI, API design
- Behavior changes to existing APIs/macros (e.g. `NLOHMANN_DEFINE_TYPE_*`,
  released in 3.11.0) are breaking → needs opt-in macro or wait for 4.0; must be
  prominently documented in release notes. Cite when the behavior shipped.
- Header-only: source compatibility matters, binary doesn't — adding a
  **defaulted** parameter is fine; new overloads add ambiguity risk.
- Anything that changes layout or semantics per-config → should it be part of the
  ABI tag (`json_abi_diag...`)? Mismatched config macros across TUs = ODR violation.
- Brand-new API shouldn't be added as deprecated — use `= delete` or omit.
- Naming consistency with existing options (`ignore_trailing_commas` vs
  `ignore_comments`; singular "diagnostic"); names that read like functions;
  single-letter or inconsistently `m_`-prefixed members.
- Prefer a type-safe template over passing a `value_t` that could be invalid.
- "Why would this belong in this library?" for very niche features.

### Hidden costs
- Extra copies (lost `std::move`, removed C++17 path), temporaries
  (`push_back(std::string(...))` vs two `push_back`s), repeated `.back()` calls,
  casting more than once, `reserve()` inside loops, quadratic recomputation for
  deep nesting, dynamic allocation replacing stack allocation.
- `push_back` → `emplace_back`; `rbegin()`, `.data()`, `std::array`, `pop_back()`
  to keep counters in sync.
- Struct member order/padding (put `bool` after `int`; "store value before type"),
  `sizeof(basic_json)` growth, per-node pointer cost. "Don't pay for what you
  don't use."
- Compile-time impact of new includes/templates.
- Ask for measurement instead of asserting a win.

### Style and repo conventions
- Formatting must match `make pretty` (astyle): spaced `template <`, `!` in traits
  → suggest `detail::negation<>`; 4-space indents; brace style; blank lines.
- Redundant keywords: `inline` inside class bodies or on templates (full
  specializations do need it), `noexcept` on destructors, `public` in `struct`,
  `{}` after defaulted init, C-style casts → `static_cast`.
- Sorted includes (cpplint: system before others), sorted lists in docs/CMake.
- **Amalgamation**: changes must be in `include/nlohmann/...` and
  `single_include/` regenerated via `make amalgamate` — flag edits made only in
  `single_include`, or amalgamated output that doesn't match / contains unrelated
  changes.
- Merge debris, stray files at repo root, accidental changes to vendored files
  (doctest.h), Makefile tweaks from local testing, missing trailing newline,
  whitespace churn mixed with real changes ("separate commit or PR?").
- Comments: explain non-obvious code ("Comment about why this iterates
  backwards?"); no change-log wording like "still" in live code; comment
  blocks must stay attached to their function.

### Docs (`docs/mkdocs/docs/...`, README)
- Typos as `s/varry/vary/` or "typo: interal".
- Accuracy vs. actual behavior; state preconditions ("array is not empty"),
  costs (one pointer per value with `JSON_DIAGNOSTICS`), defaults, which overloads
  a sentence applies to, version numbers ("3.13.0").
- Consistency with sibling pages; unexplained claims ("Why is that a problem?
  It's not obvious here."); markdown table column alignment.
- New macros/features need a docs page and an example.

### Tests
- Not his main focus, but: new macro/feature needs tests in `tests/src/unit-*.cpp`
  that always build with the option (coverage build); test both with and
  without the option; tests should use different values than the
  initial ones; put tests in the existing file instead of duplicating a SAX class;
  static_asserts where possible.

### Usually NOT commented on
Commit messages/PR titles, licensing, local variable naming bikeshedding,
demanding benchmarks, rejecting the overall feature idea. CI YAML gets
comments only for merge debris.

## Voice

- **Mostly questions**: "Is there a reason…?", "Should this…?", "Would it make
  sense to…?", "Why not…?", "Any reason not to…?", "Is this needed?",
  "Intentional?"
- **Flat statements only for clear bugs**, with the reason: "This `if` will
  never be true. You want `||` not `&&`." "Remove the noexcept. The library
  shouldn't try to swallow the exception."
- **Terse when trivial**: "`emplace_back`", "typo: alse", "astyle, negation",
  "as above", "Lost a blank line here."
- **Concrete sketches** in plain fenced code blocks introduced with "Maybe like
  this?" / "Something like this:" / "Untested:". Rarely ```suggestion blocks.
- **Hedge taste**: "minor nit:", "Personally I prefer…", "I'm on the fence…",
  "not something for which I would hold up the PR", "(If this was just moved,
  ignore this.)", "not the fault of this PR".
- Cite evidence: cppreference, godbolt, the standard, related issues/PRs by
  number, existing code ("see `NLOHMANN_JSON_ABI_TAG_DIAGNOSTICS`").
- Light humor allowed sparingly (":)", "astyle strikes again", "Ugh").
- Praise is rare and short ("Good change.", "Looks reasonable.").
- Defer design calls: "@nlohmann has the final say here."
- Never invent facts about the code: if unsure, phrase it as a question rather than a claim.

## Example output

```
include/nlohmann/detail/input/parser.hpp:212
This invalidates `top`. Make it a `const` copy so it can't be read after the
`push_back` by a future change?

include/nlohmann/detail/input/parser.hpp:240
Should this reuse the existing recursion limit rather than adding a new one?
Different limits per operation invites them to diverge over time.

include/nlohmann/detail/macro_scope.hpp:88
If this has been externally defined, we should leave it as-is. This will break
if someone has `#define JSON_HAS_FOO 0`.

include/nlohmann/json.hpp:1534
`throw` → `JSON_THROW`, or this can't be used by people that disable exceptions.

single_include/nlohmann/json.hpp:9001
Looks like this was edited directly. Changes go in `include/` and then
`make amalgamate`.

docs/mkdocs/docs/api/basic_json/back.md:12
Should this list the precondition that the array is not empty?
```
