# Releases

This section summarizes the notable changes of every release and links to the relevant documentation.
The **complete release notes** — including all changes, the download files, and their checksums — are
published on the [GitHub releases page](https://github.com/nlohmann/json/releases).

!!! info "Unreleased changes"

    This documentation is built from the `develop` branch and may describe changes that are not part of a release
    yet. Their version numbers are followed by an <span class="unreleased-version">unreleased</span> badge.

Every release has its own page with a summary of its notable changes and an overview of the API that was added or
changed in it. The API overview is generated from the "Version history" section of the
[API pages](../../api/basic_json/index.md); it is not a change log, but helps to see whether a feature is available in
the version you use.

All releases at a glance (hover a marker for its version and date):

<div class="nj-fig-wrap" markdown>
--8<-- "images/release_timeline.svg"
</div>

<p class="nj-caption" markdown>Releases from 1.0.0 to the latest one, on a time axis by year. Filled dots with a version label are minor or major releases, rings are patch releases.</p>

## Unreleased

| Release | Date | Summary |
|---------|------|---------|
| [Unreleased](unreleased.md) |  | Changes on the `develop` branch that are not part of a release yet. |

## Version 3.12.x

| Release | Date | Summary |
|---------|------|---------|
| [v3.12.0](v3.12.0.md) | 2025-04-11 | Fixes bugs found in 3.11.3 and adds several features. No public API was removed or renamed. |

## Version 3.11.x

| Release | Date | Summary |
|---------|------|---------|
| [v3.11.3](v3.11.3.md) | 2023-11-28 | Adds features and fixes bugs found in 3.11.2. All changes are backward-compatible. |
| [v3.11.2](v3.11.2.md) | 2022-08-12 | Fixes bugs found in 3.11.1 and restructures the namespace. All changes are backward-compatible. |
| [v3.11.1](v3.11.1.md) | 2022-08-01 | Fixes a regression from 3.11.0. All changes are backward-compatible. |
| [v3.11.0](v3.11.0.md) | 2022-08-01 | One of the largest releases ever. All changes are backward-compatible. |

## Version 3.10.x

| Release | Date | Summary |
|---------|------|---------|
| [v3.10.5](v3.10.5.md) | 2022-01-03 | Bug-fix release. All changes are backward-compatible. |
| [v3.10.4](v3.10.4.md) | 2021-10-16 | Fixes regressions introduced in 3.10.0. All changes are backward-compatible. |
| [v3.10.3](v3.10.3.md) | 2021-10-08 | Fixes more regressions from 3.10.0. All changes are backward-compatible. |
| [v3.10.2](v3.10.2.md) | 2021-08-26 | Re-release of 3.10.1, whose Git tag pointed at the wrong commit due to a bug in the release script. All changes are backward-compatible. |
| [v3.10.1](v3.10.1.md) | 2021-08-24 | Fixes a regression from 3.10.0. All changes are backward-compatible. |
| [v3.10.0](v3.10.0.md) | 2021-08-17 | Feature release. All changes are backward-compatible. |

## Version 3.9.x

| Release | Date | Summary |
|---------|------|---------|
| [v3.9.1](v3.9.1.md) | 2020-08-06 | Fixes two regressions from 3.9.0. All changes are backward-compatible. |
| [v3.9.0](v3.9.0.md) | 2020-07-27 | Feature release adding four long-requested features. All changes are backward-compatible. |

## Version 3.8.x

| Release | Date | Summary |
|---------|------|---------|
| [v3.8.0](v3.8.0.md) | 2020-06-14 | Feature release. All changes are backward-compatible. |

## Version 3.7.x

| Release | Date | Summary |
|---------|------|---------|
| [v3.7.3](v3.7.3.md) | 2019-11-17 | Fixes a regression from 3.7.2 that could yield quadratic complexity in destructor calls. All changes are backward-compatible. |
| [v3.7.2](v3.7.2.md) | 2019-11-10 | Fixes a stack overflow for deeply nested input by making the destructor iterative; parsing of JSON text is now bounded only by available memory (the binary-format parsers still recurse). All changes are backward-compatible. |
| [v3.7.1](v3.7.1.md) | 2019-11-06 | Bug-fix release. All changes are backward-compatible. |
| [v3.7.0](v3.7.0.md) | 2019-07-28 | Convenience features and house-keeping. All changes are backward-compatible. |

## Version 3.6.x

| Release | Date | Summary |
|---------|------|---------|
| [v3.6.1](v3.6.1.md) | 2019-03-20 | Fixes a regression (GCC 7/8 compilation) and a `<Windows.h>` build error introduced in 3.6.0. All changes are backward-compatible. |
| [v3.6.0](v3.6.0.md) | 2019-03-20 | Feature release. All changes are backward-compatible. |

## Version 3.5.x

| Release | Date | Summary |
|---------|------|---------|
| [v3.5.0](v3.5.0.md) | 2018-12-22 | Feature release. All changes are backward-compatible. |

## Version 3.4.x

| Release | Date | Summary |
|---------|------|---------|
| [v3.4.0](v3.4.0.md) | 2018-10-30 | Feature release. All changes are backward-compatible. |

## Version 3.3.x

| Release | Date | Summary |
|---------|------|---------|
| [v3.3.0](v3.3.0.md) | 2018-10-05 | Feature release. All changes are backward-compatible. |

## Version 3.2.x

| Release | Date | Summary |
|---------|------|---------|
| [v3.2.0](v3.2.0.md) | 2018-08-20 | Feature release. All changes are backward-compatible. |

## Version 3.1.x

| Release | Date | Summary |
|---------|------|---------|
| [v3.1.2](v3.1.2.md) | 2018-03-14 | Bug-fix release. All changes are backward-compatible. |
| [v3.1.1](v3.1.1.md) | 2018-02-13 | Bug-fix release. All changes are backward-compatible. |
| [v3.1.0](v3.1.0.md) | 2018-02-01 | Feature release. All changes are backward-compatible. |

## Version 3.0.x

| Release | Date | Summary |
|---------|------|---------|
| [v3.0.1](v3.0.1.md) | 2017-12-29 | Fixes small issues in the [JSON Pointer](../../features/json_pointer.md) and [JSON Patch](../../features/json_patch.md) implementations (invalid "copy" targets and non-integer array indices). All changes are backward-compatible. |
| [v3.0.0](v3.0.0.md) | 2017-12-17 | First 3.x release — a major release with breaking changes (see the [migration guide](../../integration/migration_guide.md)). |

## Version 2.1.x

| Release | Date | Summary |
|---------|------|---------|
| [v2.1.1](v2.1.1.md) | 2017-02-25 | Bug-fix release. All changes are backward-compatible. |
| [v2.1.0](v2.1.0.md) | 2017-01-28 | Feature release. All changes are backward-compatible. |

## Version 2.0.x

| Release | Date | Summary |
|---------|------|---------|
| [v2.0.10](v2.0.10.md) | 2017-01-02 | Fixes several security-relevant bugs in the CBOR and MessagePack parsers found by OSS-Fuzz. All changes are backward-compatible. |
| [v2.0.9](v2.0.9.md) | 2016-12-16 | Adds the [CBOR](../../features/binary_formats/cbor.md) and [MessagePack](../../features/binary_formats/messagepack.md) binary formats. All changes are backward-compatible. |
| [v2.0.8](v2.0.8.md) | 2016-12-02 | Adds the [`emplace`](../../api/basic_json/emplace.md) and [`emplace_back`](../../api/basic_json/emplace_back.md) functions and improves parsing and serialization performance. All changes are backward-compatible. |
| [v2.0.7](v2.0.7.md) | 2016-11-02 | Fixes several parser bugs found through the "Parsing JSON is a Minefield" study (short files, encoding detection, surrogate pairs). All changes are backward-compatible. |
| [v2.0.6](v2.0.6.md) | 2016-10-15 | Fixes [`operator[]`](../../api/basic_json/operator%5B%5D.md) for [JSON pointers](../../features/json_pointer.md) so that it creates missing values like the other overloads. All changes are backward-compatible. |
| [v2.0.5](v2.0.5.md) | 2016-09-14 | Fixes a remaining stream end-of-file detection bug in the parser. All changes are backward-compatible. |
| [v2.0.4](v2.0.4.md) | 2016-09-11 | Fixes stream end-of-file detection in the parser. All changes are backward-compatible. |
| [v2.0.3](v2.0.3.md) | 2016-08-31 | Generalizes the parser to accept any contiguous sequence of one-byte elements and deprecates the input-stream constructor in favor of the [`parse`](../../api/basic_json/parse.md) function. All changes are backward-compatible. |
| [v2.0.2](v2.0.2.md) | 2016-07-31 | Overhauls the parser (now rejecting unescaped control characters), tightens the class invariants, and cleans up the code. All changes are backward-compatible. |
| [v2.0.1](v2.0.1.md) | 2016-06-28 | Fixes a performance regression in the [`dump`](../../api/basic_json/dump.md) function by adjusting the stream locale once per serialization. All changes are backward-compatible. |
| [v2.0.0](v2.0.0.md) | 2016-06-24 | Feature release with a minor (potentially non-backward-compatible) API change from added `noexcept` and `constexpr` specifiers. |

## Version 1.1.x

| Release | Date | Summary |
|---------|------|---------|
| [v1.1.0](v1.1.0.md) | 2016-01-24 | Bug-fix and feature release. All changes are backward-compatible. |

## Version 1.0.x

| Release | Date | Summary |
|---------|------|---------|
| [v1.0.0](v1.0.0.md) | 2015-12-28 | First official release. |

## See also

- [Migration Guide](../../integration/migration_guide.md) — how to future-proof your code for the next
  major version and replace deprecated functions.
