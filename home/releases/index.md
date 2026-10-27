# Releases

This section summarizes the notable changes of every release and links to the relevant documentation. The **complete release notes** — including all changes, the download files, and their checksums — are published on the [GitHub releases page](https://github.com/nlohmann/json/releases).

Unreleased changes

This documentation is built from the `develop` branch and may describe changes that are not part of a release yet. Their version numbers are followed by an unreleased badge.

Every release has its own page with a summary of its notable changes and an overview of the API that was added or changed in it. The API overview is generated from the "Version history" section of the [API pages](https://json.nlohmann.me/api/basic_json/index.md); it is not a change log, but helps to see whether a feature is available in the version you use.

All releases at a glance (hover a marker for its version and date):

From the first commit (diamond) in 2013 to the latest release, on a time axis by year. Filled dots with a version label are minor or major releases, rings are patch releases.

## Unreleased

| Release                                                                  | Date | Summary                                                             |
| ------------------------------------------------------------------------ | ---- | ------------------------------------------------------------------- |
| [Unreleased](https://json.nlohmann.me/home/releases/unreleased/index.md) |      | Changes on the `develop` branch that are not part of a release yet. |

## Version 3.12.x

| Release                                                            | Date       | Summary                                                                                                                                                                                                                                                 |
| ------------------------------------------------------------------ | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [v3.12.0](https://json.nlohmann.me/home/releases/v3.12.0/index.md) | 2025-04-11 | Fixes bugs found in 3.11.3 and adds several features. No public API was removed or renamed. **Highlights:** diagnostic byte positions (`start_pos`/`end_pos`); templated conversion macros and `NLOHMANN_DEFINE_DERIVED_TYPE`; `std::optional` support. |

## Version 3.11.x

| Release                                                            | Date       | Summary                                                                                                                                                                                                                                        |
| ------------------------------------------------------------------ | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [v3.11.3](https://json.nlohmann.me/home/releases/v3.11.3/index.md) | 2023-11-28 | Adds features and fixes bugs found in 3.11.2. All changes are backward-compatible. **Highlights:** custom base class for `basic_json`; serialization-only conversion macros; Bazel and Swift Package Manager support.                          |
| [v3.11.2](https://json.nlohmann.me/home/releases/v3.11.2/index.md) | 2022-08-12 | Fixes bugs found in 3.11.1 and restructures the namespace. All changes are backward-compatible. **Highlights:** fixes `value` for strings and size types; restores `json_pointer` as associative-container key; restructured inline namespace. |
| [v3.11.1](https://json.nlohmann.me/home/releases/v3.11.1/index.md) | 2022-08-01 | Fixes a regression from 3.11.0. All changes are backward-compatible. **Highlights:** restores the global `_json` and `_json_pointer` literals.                                                                                                 |
| [v3.11.0](https://json.nlohmann.me/home/releases/v3.11.0/index.md) | 2022-08-01 | One of the largest releases ever. All changes are backward-compatible. **Highlights:** `std::string_view` keys; BJData binary format; C++20 support including `operator<=>`.                                                                   |

## Version 3.10.x

| Release                                                            | Date       | Summary                                                                                                                                                                                                                                            |
| ------------------------------------------------------------------ | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [v3.10.5](https://json.nlohmann.me/home/releases/v3.10.5/index.md) | 2022-01-03 | Bug-fix release. All changes are backward-compatible. **Highlights:** guards the `std::filesystem` conversions with `JSON_HAS_FILESYSTEM`.                                                                                                         |
| [v3.10.4](https://json.nlohmann.me/home/releases/v3.10.4/index.md) | 2021-10-16 | Fixes regressions introduced in 3.10.0. All changes are backward-compatible. **Highlights:** fixes the `std::filesystem::path` conversion; fixes types with explicit defaulted constructors; fixes `std::find`/`std::remove` return values.        |
| [v3.10.3](https://json.nlohmann.me/home/releases/v3.10.3/index.md) | 2021-10-08 | Fixes more regressions from 3.10.0. All changes are backward-compatible. **Highlights:** fixes extended-diagnostics assertions in `update` and array insertion; custom allocators for binary output; conversion from `begin()`/`end()`-only types. |
| [v3.10.2](https://json.nlohmann.me/home/releases/v3.10.2/index.md) | 2021-08-26 | Re-release of 3.10.1, whose Git tag pointed at the wrong commit due to a bug in the release script. All changes are backward-compatible. **Highlights:** re-release of 3.10.1 with the correct Git tag.                                            |
| [v3.10.1](https://json.nlohmann.me/home/releases/v3.10.1/index.md) | 2021-08-24 | Fixes a regression from 3.10.0. All changes are backward-compatible. **Highlights:** fixes an extended-diagnostics assertion with `ordered_json`; hardens the GDB pretty-printer.                                                                  |
| [v3.10.0](https://json.nlohmann.me/home/releases/v3.10.0/index.md) | 2021-08-17 | Feature release. All changes are backward-compatible. **Highlights:** extended diagnostic messages (`JSON_DIAGNOSTICS`); GDB pretty-printer; CBOR tag storage.                                                                                     |

## Version 3.9.x

| Release                                                          | Date       | Summary                                                                                                                                                                            |
| ---------------------------------------------------------------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [v3.9.1](https://json.nlohmann.me/home/releases/v3.9.1/index.md) | 2020-08-06 | Fixes two regressions from 3.9.0. All changes are backward-compatible. **Highlights:** accepts consecutive comments; completes the `ordered_json` interface.                       |
| [v3.9.0](https://json.nlohmann.me/home/releases/v3.9.0/index.md) | 2020-07-27 | Feature release adding four long-requested features. All changes are backward-compatible. **Highlights:** comment parsing; `ordered_json`; switch to disable implicit conversions. |

## Version 3.8.x

| Release                                                          | Date       | Summary                                                                                                                                                                                                              |
| ---------------------------------------------------------------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [v3.8.0](https://json.nlohmann.me/home/releases/v3.8.0/index.md) | 2020-06-14 | Feature release. All changes are backward-compatible. **Highlights:** binary value type for CBOR, BSON, and MessagePack; input adapters for any `LegacyInputIterator` container; fixes `contains` for JSON pointers. |

## Version 3.7.x

| Release                                                          | Date       | Summary                                                                                                                                                                                                                                                                                                             |
| ---------------------------------------------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [v3.7.3](https://json.nlohmann.me/home/releases/v3.7.3/index.md) | 2019-11-17 | Fixes a regression from 3.7.2 that could yield quadratic complexity in destructor calls. All changes are backward-compatible. **Highlights:** fixes quadratic complexity in destructor calls.                                                                                                                       |
| [v3.7.2](https://json.nlohmann.me/home/releases/v3.7.2/index.md) | 2019-11-10 | Fixes a stack overflow for deeply nested input by making the destructor iterative; parsing of JSON text is now bounded only by available memory (the binary-format parsers still recurse). All changes are backward-compatible. **Highlights:** iterative destructor fixes a stack overflow on deeply nested input. |
| [v3.7.1](https://json.nlohmann.me/home/releases/v3.7.1/index.md) | 2019-11-06 | Bug-fix release. All changes are backward-compatible. **Highlights:** fixes a crash when serializing the minimum `std::int64_t`; fixes `contains` for JSON pointers; `items` with custom string types.                                                                                                              |
| [v3.7.0](https://json.nlohmann.me/home/releases/v3.7.0/index.md) | 2019-07-28 | Convenience features and house-keeping. All changes are backward-compatible. **Highlights:** `contains` overload for JSON pointers; generic `to_string`; return value for `emplace_back`.                                                                                                                           |

## Version 3.6.x

| Release                                                          | Date       | Summary                                                                                                                                                                                                                       |
| ---------------------------------------------------------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [v3.6.1](https://json.nlohmann.me/home/releases/v3.6.1/index.md) | 2019-03-20 | Fixes a regression (GCC 7/8 compilation) and a `<Windows.h>` build error introduced in 3.6.0. All changes are backward-compatible. **Highlights:** fixes a GCC 7/8 compilation regression; fixes a `<Windows.h>` build error. |
| [v3.6.0](https://json.nlohmann.me/home/releases/v3.6.0/index.md) | 2019-03-20 | Feature release. All changes are backward-compatible. **Highlights:** reworked JSON pointer interface; `contains` function; faster integer serialization.                                                                     |

## Version 3.5.x

| Release                                                          | Date       | Summary                                                                                                                                                          |
| ---------------------------------------------------------------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [v3.5.0](https://json.nlohmann.me/home/releases/v3.5.0/index.md) | 2018-12-22 | Feature release. All changes are backward-compatible. **Highlights:** structured bindings via `items`; reading from `FILE*`; fixes `eofbit` handling on streams. |

## Version 3.4.x

| Release                                                          | Date       | Summary                                                                                                                                                |
| ---------------------------------------------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [v3.4.0](https://json.nlohmann.me/home/releases/v3.4.0/index.md) | 2018-10-30 | Feature release. All changes are backward-compatible. **Highlights:** BSON support; Unicode error handlers for `dump`; `NLOHMANN_JSON_SERIALIZE_ENUM`. |

## Version 3.3.x

| Release                                                          | Date       | Summary                                                                                                                        |
| ---------------------------------------------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------ |
| [v3.3.0](https://json.nlohmann.me/home/releases/v3.3.0/index.md) | 2018-10-05 | Feature release. All changes are backward-compatible. **Highlights:** GCC 4.8 support; `get_to`; overhauled CMake integration. |

## Version 3.2.x

| Release                                                          | Date       | Summary                                                                                                                                                                    |
| ---------------------------------------------------------------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [v3.2.0](https://json.nlohmann.me/home/releases/v3.2.0/index.md) | 2018-08-20 | Feature release. All changes are backward-compatible. **Highlights:** SAX interface and non-recursive parser; parsing from wide strings; conversion to `std::string_view`. |

## Version 3.1.x

| Release                                                          | Date       | Summary                                                                                                                                                                                                  |
| ---------------------------------------------------------------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [v3.1.2](https://json.nlohmann.me/home/releases/v3.1.2/index.md) | 2018-03-14 | Bug-fix release. All changes are backward-compatible. **Highlights:** fixes a memory leak in the parser callback; user-defined string types in parser and serializer.                                    |
| [v3.1.1](https://json.nlohmann.me/home/releases/v3.1.1/index.md) | 2018-02-13 | Bug-fix release. All changes are backward-compatible. **Highlights:** fixes parsing of indefinite-length CBOR strings; fixes a user-defined conversion to vector types; fixes UBJSON overflow detection. |
| [v3.1.0](https://json.nlohmann.me/home/releases/v3.1.0/index.md) | 2018-02-01 | Feature release. All changes are backward-compatible. **Highlights:** UBJSON support; JSON Merge Patch; Grisu2 floating-point output.                                                                    |

## Version 3.0.x

| Release                                                          | Date       | Summary                                                                                                                                                                                                                                                                                                                                                                                          |
| ---------------------------------------------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [v3.0.1](https://json.nlohmann.me/home/releases/v3.0.1/index.md) | 2017-12-29 | Fixes small issues in the [JSON Pointer](https://json.nlohmann.me/features/json_pointer/index.md) and [JSON Patch](https://json.nlohmann.me/features/json_patch/index.md) implementations (invalid "copy" targets and non-integer array indices). All changes are backward-compatible. **Highlights:** fixes invalid JSON Patch "copy" targets; fixes non-integer array indices in JSON Pointer. |
| [v3.0.0](https://json.nlohmann.me/home/releases/v3.0.0/index.md) | 2017-12-17 | First 3.x release — a major release with breaking changes (see the [migration guide](https://json.nlohmann.me/integration/migration_guide/index.md)). **Highlights:** user-defined exceptions with identifiers; non-throwing `accept` and `allow_exceptions`; `update` to merge objects.                                                                                                         |

## Version 2.1.x

| Release                                                          | Date       | Summary                                                                                                                                                                                         |
| ---------------------------------------------------------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [v2.1.1](https://json.nlohmann.me/home/releases/v2.1.1/index.md) | 2017-02-25 | Bug-fix release. All changes are backward-compatible. **Highlights:** locale-independent number parsing and serialization; correct floating-point round-tripping; GPG-signed commits and files. |
| [v2.1.0](https://json.nlohmann.me/home/releases/v2.1.0/index.md) | 2017-01-28 | Feature release. All changes are backward-compatible. **Highlights:** conversions from and to arbitrary user-defined types; `meta` function; `JSON_NOEXCEPTION`.                                |

## Version 2.0.x

| Release                                                            | Date       | Summary                                                                                                                                                                                                                                                                                                                                                                                              |
| ------------------------------------------------------------------ | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [v2.0.10](https://json.nlohmann.me/home/releases/v2.0.10/index.md) | 2017-01-02 | Fixes several security-relevant bugs in the CBOR and MessagePack parsers found by OSS-Fuzz. All changes are backward-compatible. **Highlights:** fixes security-relevant bugs in the CBOR parser; fixes security-relevant bugs in the MessagePack parser.                                                                                                                                            |
| [v2.0.9](https://json.nlohmann.me/home/releases/v2.0.9/index.md)   | 2016-12-16 | Adds the [CBOR](https://json.nlohmann.me/features/binary_formats/cbor/index.md) and [MessagePack](https://json.nlohmann.me/features/binary_formats/messagepack/index.md) binary formats. All changes are backward-compatible. **Highlights:** CBOR support; MessagePack support.                                                                                                                     |
| [v2.0.8](https://json.nlohmann.me/home/releases/v2.0.8/index.md)   | 2016-12-02 | Adds the [`emplace`](https://json.nlohmann.me/api/basic_json/emplace/index.md) and [`emplace_back`](https://json.nlohmann.me/api/basic_json/emplace_back/index.md) functions and improves parsing and serialization performance. All changes are backward-compatible. **Highlights:** `emplace` and `emplace_back`; faster parsing; faster serialization.                                            |
| [v2.0.7](https://json.nlohmann.me/home/releases/v2.0.7/index.md)   | 2016-11-02 | Fixes several parser bugs found through the "Parsing JSON is a Minefield" study (short files, encoding detection, surrogate pairs). All changes are backward-compatible. **Highlights:** fixes short-file handling; fixes encoding detection; fixes surrogate pairs.                                                                                                                                 |
| [v2.0.6](https://json.nlohmann.me/home/releases/v2.0.6/index.md)   | 2016-10-15 | Fixes [`operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md) for [JSON pointers](https://json.nlohmann.me/features/json_pointer/index.md) so that it creates missing values like the other overloads. All changes are backward-compatible. **Highlights:** `operator[]` creates missing values for JSON pointers.                                                           |
| [v2.0.5](https://json.nlohmann.me/home/releases/v2.0.5/index.md)   | 2016-09-14 | Fixes a remaining stream end-of-file detection bug in the parser. All changes are backward-compatible. **Highlights:** fixes a remaining stream end-of-file bug.                                                                                                                                                                                                                                     |
| [v2.0.4](https://json.nlohmann.me/home/releases/v2.0.4/index.md)   | 2016-09-11 | Fixes stream end-of-file detection in the parser. All changes are backward-compatible. **Highlights:** fixes stream end-of-file detection.                                                                                                                                                                                                                                                           |
| [v2.0.3](https://json.nlohmann.me/home/releases/v2.0.3/index.md)   | 2016-08-31 | Generalizes the parser to accept any contiguous sequence of one-byte elements and deprecates the input-stream constructor in favor of the [`parse`](https://json.nlohmann.me/api/basic_json/parse/index.md) function. All changes are backward-compatible. **Highlights:** parser accepts any contiguous sequence of one-byte elements; deprecates the input-stream constructor in favor of `parse`. |
| [v2.0.2](https://json.nlohmann.me/home/releases/v2.0.2/index.md)   | 2016-07-31 | Overhauls the parser (now rejecting unescaped control characters), tightens the class invariants, and cleans up the code. All changes are backward-compatible. **Highlights:** overhauled parser rejecting unescaped control characters; tighter class invariants; code cleanup.                                                                                                                     |
| [v2.0.1](https://json.nlohmann.me/home/releases/v2.0.1/index.md)   | 2016-06-28 | Fixes a performance regression in the [`dump`](https://json.nlohmann.me/api/basic_json/dump/index.md) function by adjusting the stream locale once per serialization. All changes are backward-compatible. **Highlights:** fixes a performance regression in `dump`.                                                                                                                                 |
| [v2.0.0](https://json.nlohmann.me/home/releases/v2.0.0/index.md)   | 2016-06-24 | Feature release with a minor (potentially non-backward-compatible) API change from added `noexcept` and `constexpr` specifiers. **Highlights:** JSON Pointer support in `at` and `operator[]`, plus `flatten` and `unflatten`; JSON Patch via `diff` and `patch`; unsigned 64-bit integers.                                                                                                          |

## Version 1.1.x

| Release                                                          | Date       | Summary                                                                                                                                                  |
| ---------------------------------------------------------------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [v1.1.0](https://json.nlohmann.me/home/releases/v1.1.0/index.md) | 2016-01-24 | Bug-fix and feature release. All changes are backward-compatible. **Highlights:** improved floating-point round-tripping; `get_ref`; runtime assertions. |

## Version 1.0.x

| Release                                                          | Date       | Summary                 |
| ---------------------------------------------------------------- | ---------- | ----------------------- |
| [v1.0.0](https://json.nlohmann.me/home/releases/v1.0.0/index.md) | 2015-12-28 | First official release. |

## See also

- [Migration Guide](https://json.nlohmann.me/integration/migration_guide/index.md) — how to future-proof your code for the next major version and replace deprecated functions.
- [Roadmap: Version 4.0](https://json.nlohmann.me/community/roadmap/#version-40) — what the next major version will change and how to try it today.
