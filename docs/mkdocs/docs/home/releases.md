# Releases

This page summarizes the notable changes of every release and links to the relevant documentation.
The **complete release notes** — including all changes, the download files, and their checksums — are
published on the [GitHub releases page](https://github.com/nlohmann/json/releases).

## v3.12.0 (2025-04-11)

Fixes bugs found in 3.11.3 and adds several features. All changes are backward-compatible.

- Adds diagnostic byte positions via [`JSON_DIAGNOSTIC_POSITIONS`](../api/macros/json_diagnostic_positions.md),
  exposed through the new [`start_pos`](../api/basic_json/start_pos.md) and
  [`end_pos`](../api/basic_json/end_pos.md) member functions.
- Makes the [conversion macros](../features/arbitrary_types.md#simplify-your-life-with-macros)
  templated (so they also work with [`ordered_json`](../api/ordered_json.md)) and adds
  [`NLOHMANN_DEFINE_DERIVED_TYPE`](../api/macros/nlohmann_define_derived_type.md) for derived classes.
- Adds `std::optional` support (C++17) and lets [`patch`](../api/basic_json/patch.md),
  [`diff`](../api/basic_json/diff.md), and [`flatten`](../api/basic_json/flatten.md) work with
  arbitrary string types.
- Extends the [binary formats](../features/binary_formats/index.md):
  [BJData](../features/binary_formats/bjdata.md) draft 3 and unsigned 64-bit integers for
  [BSON](../features/binary_formats/bson.md).
- Adds multidimensional C-array conversion and UTF-8 encoded `std::filesystem::path` conversions, and
  lowers the minimum [CMake](../integration/cmake.md) version to allow CMake 4.0.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.12.0).

## v3.11.3 (2023-11-28)

Adds features and fixes bugs found in 3.11.2. All changes are backward-compatible.

- Adds a [custom base class](../api/basic_json/json_base_class_t.md) as a node customization point.
- Adds serialization-only [conversion macros](../features/macros.md)
  (`NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE` and `NLOHMANN_DEFINE_TYPE_INTRUSIVE_ONLY_SERIALIZE`)
  and a clearer parse error for empty input.
- Adds [Bazel](../integration/package_managers.md#bazel) and
  [Swift Package Manager](../integration/package_managers.md#swift-package-manager) build support.
- Fixes custom allocators, a memory leak in [`adl_serializer`](../api/adl_serializer/to_json.md)'s
  `to_json`, initializer-list construction when `size_type` is not `int`, and many compiler warnings.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.11.3).

## v3.11.2 (2022-08-12)

Fixes bugs found in 3.11.1 and restructures the namespace. All changes are backward-compatible.

- Fixes the [`value`](../api/basic_json/value.md) function (broken for strings, size types, and
  `nullptr` in 3.11.0) and makes `json_fwd.hpp` self-contained.
- Restores using [`json_pointer`](../api/json_pointer/index.md) as a key in associative containers and
  comparing it with strings.
- Restructures the inline [namespace](../features/namespace.md) and allows disabling the version
  component, and avoids heap allocations in the [BJData](../features/binary_formats/bjdata.md) parser.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.11.2).

## v3.11.1 (2022-08-01)

Fixes a regression from 3.11.0. All changes are backward-compatible.

- Restores the global [user-defined string literals](../api/macros/json_use_global_udls.md)
  [`operator""_json`](../api/operator_literal_json.md) and
  [`operator""_json_pointer`](../api/operator_literal_json_pointer.md), which 3.11.0 had moved into a
  namespace by default.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.11.1).

## v3.11.0 (2022-08-01)

One of the largest releases ever. All changes are backward-compatible.

- Allows `std::string_view` as object keys in [`at`](../api/basic_json/at.md),
  [`operator[]`](../api/basic_json/operator%5B%5D.md), [`value`](../api/basic_json/value.md),
  [`erase`](../api/basic_json/erase.md), [`find`](../api/basic_json/find.md),
  [`contains`](../api/basic_json/contains.md), and [`count`](../api/basic_json/count.md).
- Adds the [BJData](../features/binary_formats/bjdata.md) binary format (the fifth supported format).
- Improves C++20 support, including [`operator<=>`](../api/basic_json/operator_spaceship.md) and
  `<ranges>`-compatible iterators.
- Adds a versioned, ABI-tagged inline [namespace](../features/namespace.md)
  ([`NLOHMANN_JSON_NAMESPACE`](../api/macros/nlohmann_json_namespace.md)) and the option to move the
  UDLs out of the global namespace ([`JSON_USE_GLOBAL_UDLS`](../api/macros/json_use_global_udls.md)).
- Adds [`patch_inplace`](../api/basic_json/patch_inplace.md), default values for the
  [conversion macros](../features/arbitrary_types.md#simplify-your-life-with-macros), and an option to
  disable enum serialization ([`JSON_DISABLE_ENUM_SERIALIZATION`](../api/macros/json_disable_enum_serialization.md)).

This release introduced a UDL regression that was fixed in
[3.11.1](https://github.com/nlohmann/json/releases/tag/v3.11.1).
[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.11.0).

## v3.10.5 (2022-01-03)

Bug-fix release. All changes are backward-compatible.

- Guards the `std::filesystem` conversions behind compiler-support checks
  ([`JSON_HAS_FILESYSTEM`](../api/macros/json_has_filesystem.md)), which can be set to `0` to disable
  them altogether.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.10.5).

## v3.10.4 (2021-10-16)

Fixes regressions introduced in 3.10.0. All changes are backward-compatible.

- Fixes the `std::filesystem::path` conversion (which could trigger a stack overflow and broke
  compilation on Windows).
- Fixes compilation for types with an explicit defaulted constructor and for code relying on the
  return values of `std::find` and `std::remove`.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.10.4).

## v3.10.3 (2021-10-08)

Fixes more regressions from 3.10.0. All changes are backward-compatible.

- Fixes [extended-diagnostics](../api/macros/json_diagnostics.md) assertions triggered by
  [`update`](../api/basic_json/update.md) and by inserting into arrays.
- Supports custom allocators when writing binary formats into a `std::vector`, and allows conversion
  from types that only provide `begin()`/`end()`.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.10.3).

## v3.10.2 (2021-08-26)

Re-release of 3.10.1, whose Git tag pointed at the wrong commit due to a bug in the release script.
All changes are backward-compatible.
[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.10.2).

## v3.10.1 (2021-08-24)

Fixes a regression from 3.10.0. All changes are backward-compatible.

- Fixes an [extended-diagnostics](../api/macros/json_diagnostics.md) assertion triggered when used
  with [`ordered_json`](../api/ordered_json.md), and hardens the GDB pretty-printer.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.10.1).

## v3.10.0 (2021-08-17)

Feature release. All changes are backward-compatible.

- Adds [extended diagnostic messages](../api/macros/json_diagnostics.md)
  ([`JSON_DIAGNOSTICS`](../api/macros/json_diagnostics.md)) that prepend a JSON pointer to exception
  messages to pinpoint the offending value.
- Adds a GDB pretty-printer and a [`cbor_tag_handler_t`](../api/basic_json/cbor_tag_handler_t.md)
  `store` option to keep CBOR tags as binary subtypes.
- Supports containers with non-default-constructible types and parsing from `std::byte`.
- Adds [`JSON_NO_IO`](../api/macros/json_no_io.md) to exclude the I/O headers and the
  [`JSON_HAS_CPP_*`](../api/macros/json_has_cpp_11.md) macros to override the detected C++ standard.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.10.0).

## v3.9.1 (2020-08-06)

Fixes two regressions from 3.9.0. All changes are backward-compatible.

- Accepts consecutive [comments](../features/comments.md) and completes the
  [`ordered_json`](../api/ordered_json.md) interface (e.g. `ordered_json::parse`).

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.9.1).

## v3.9.0 (2020-07-27)

Feature release adding four long-requested features. All changes are backward-compatible.

- Optional [comment](../features/comments.md) parsing in [`parse`](../api/basic_json/parse.md) via the
  `ignore_comments` parameter.
- [`ordered_json`](../api/ordered_json.md) to preserve the [insertion order](../features/object_order.md)
  of object keys.
- An option to switch off [implicit conversions](../api/macros/json_use_implicit_conversions.md).
- The [`NLOHMANN_DEFINE_TYPE_*`](../features/arbitrary_types.md#simplify-your-life-with-macros)
  convenience macros, plus high-precision-number support for
  [UBJSON](../features/binary_formats/ubjson.md) and CBOR tag handling.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.9.0).

## v3.8.0 (2020-06-14)

Feature release. All changes are backward-compatible.

- Introduces a [binary value](../features/binary_values.md) type that is read from and written to
  [CBOR](../features/binary_formats/cbor.md), [BSON](../features/binary_formats/bson.md), and
  [MessagePack](../features/binary_formats/messagepack.md), and can be shared between formats.
- Generalizes the input adapters to read from any `LegacyInputIterator` container (3–10 % faster
  parsing).
- Fixes [`contains`](../api/basic_json/contains.md) for JSON pointers and makes the binary
  [`from_cbor`](../api/basic_json/from_cbor.md)/[`from_msgpack`](../api/basic_json/from_msgpack.md)/etc.
  functions respect `allow_exceptions`.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.8.0).

## v3.7.3 (2019-11-17)

Fixes a regression from 3.7.2 that could yield quadratic complexity in destructor calls. All changes
are backward-compatible. [Full release notes](https://github.com/nlohmann/json/releases/tag/v3.7.3).

## v3.7.2 (2019-11-10)

Fixes a stack overflow for deeply nested input by making the destructor iterative; parsing is now
bounded only by available memory. All changes are backward-compatible.
[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.7.2).

## v3.7.1 (2019-11-06)

Bug-fix release. All changes are backward-compatible.

- Fixes a segmentation fault when serializing the `std::int64_t` minimum value and fixes
  [`contains`](../api/basic_json/contains.md) for JSON pointers.
- Allows [`items`](../api/basic_json/items.md) with a custom string type and makes `json_pointer::back`
  `const`.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.7.1).

## v3.7.0 (2019-07-28)

Convenience features and house-keeping. All changes are backward-compatible.

- Adds a [`contains`](../api/basic_json/contains.md) overload that checks a JSON pointer without
  throwing, a generic `to_string`, and a return value for
  [`emplace_back`](../api/basic_json/emplace_back.md).

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.7.0).

## v3.6.1 (2019-03-20)

Fixes a regression (GCC 7/8 compilation) and a `<Windows.h>` build error introduced in 3.6.0. All
changes are backward-compatible. [Full release notes](https://github.com/nlohmann/json/releases/tag/v3.6.1).

## v3.6.0 (2019-03-20)

Feature release. All changes are backward-compatible.

- Reworks the [JSON pointer](../features/json_pointer.md) interface (`operator/`, `push_back`,
  `parent_pointer`, …).
- Adds a [`contains`](../api/basic_json/contains.md) function to test for an object key and greatly
  improves the performance of integer serialization.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.6.0).

## v3.5.0 (2018-12-22)

Feature release. All changes are backward-compatible.

- Adds structured-binding support via the [`items`](../api/basic_json/items.md) function and reading
  from `FILE*` in the [`parse`](../api/basic_json/parse.md) function.
- Fixes the `eofbit` handling on input streams and a bug in the BSON SAX parser.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.5.0).

## v3.4.0 (2018-10-30)

Feature release. All changes are backward-compatible.

- Adds [BSON](../features/binary_formats/bson.md) read/write support.
- Adds configurable Unicode error handlers to [`dump`](../api/basic_json/dump.md) (throw, replace with
  U+FFFD, or ignore) and the
  [`NLOHMANN_JSON_SERIALIZE_ENUM`](../api/macros/nlohmann_json_serialize_enum.md) macro for
  [enum conversion](../features/enum_conversion.md).
- Improves parse-error messages with line/column positions and context.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.4.0).

## v3.3.0 (2018-10-05)

Feature release. All changes are backward-compatible.

- Adds GCC 4.8 support, the [`get_to`](../api/basic_json/get_to.md) function, and an overhauled and
  documented [CMake](../integration/cmake.md) integration.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.3.0).

## v3.2.0 (2018-08-20)

Feature release. All changes are backward-compatible.

- Adds a [SAX interface](../features/parsing/sax_interface.md) and a non-recursive parser.
- Adds parsing from wide-string types (`std::wstring`, `std::u16string`, `std::u32string`) and
  `std::string_view` (C++17), and round-tripping of `std::map`/`std::unordered_map` with non-string
  keys.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.2.0).

## v3.1.2 (2018-03-14)

Bug-fix release. All changes are backward-compatible.

- Fixes a memory leak in the parser callback and adds user-defined string-type support to the parser
  and serializer.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.1.2).

## v3.1.1 (2018-02-13)

Bug-fix release. All changes are backward-compatible.

- Fixes parsing of indefinite-length CBOR strings, a user-defined conversion to vector types, and
  overflow detection for UBJSON containers.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.1.1).

## v3.1.0 (2018-02-01)

Feature release. All changes are backward-compatible.

- Adds [UBJSON](../features/binary_formats/ubjson.md) read/write support and
  [JSON Merge Patch](../features/merge_patch.md) via [`merge_patch`](../api/basic_json/merge_patch.md).
- Switches to the Grisu2 algorithm for short, round-trippable floating-point output, and splits the
  header into [multiple files](../integration/index.md) with a forward-declaration header.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.1.0).

## v3.0.1 (2017-12-29)

Fixes small issues in the [JSON Pointer](../features/json_pointer.md) and
[JSON Patch](../features/json_patch.md) implementations (invalid "copy" targets and non-integer array
indices). All changes are backward-compatible.
[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.0.1).

## v3.0.0 (2017-12-17)

First 3.x release — a major release with breaking changes (see the
[migration guide](../integration/migration_guide.md)).

- Introduces user-defined [exceptions](exceptions.md) (`json::exception` and subtypes, each with an
  identifier).
- Adds a non-throwing [`accept`](../api/basic_json/accept.md) function and an `allow_exceptions` flag
  for [`parse`](../api/basic_json/parse.md), and an [`update`](../api/basic_json/update.md) function to
  merge objects.
- Adds streaming for CBOR and MessagePack and allows storing NaN/infinity.
- Non-UTF-8 strings now throw on serialization, and the iterator category changed to bidirectional.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.0.0).

## v2.1.1 (2017-02-25)

Bug-fix release. All changes are backward-compatible.

- Makes number parsing and serialization locale-independent with correct floating-point
  round-tripping; released files are now GPG-signed.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v2.1.1).

## v2.1.0 (2017-01-28)

Feature release. All changes are backward-compatible.

- Adds conversions from and to [arbitrary user-defined types](../features/arbitrary_types.md) via
  `to_json`/`from_json`, the [`meta`](../api/basic_json/meta.md) function, and the option to switch off
  exceptions ([`JSON_NOEXCEPTION`](../api/macros/json_noexception.md)).

[Full release notes](https://github.com/nlohmann/json/releases/tag/v2.1.0).

## v2.0.10 (2017-01-02)

Fixes several security-relevant bugs in the CBOR and MessagePack parsers found by OSS-Fuzz. All
changes are backward-compatible. [Full release notes](https://github.com/nlohmann/json/releases/tag/v2.0.10).

## v2.0.9 (2016-12-16)

Adds the [CBOR](../features/binary_formats/cbor.md) and
[MessagePack](../features/binary_formats/messagepack.md) binary formats. All changes are
backward-compatible. [Full release notes](https://github.com/nlohmann/json/releases/tag/v2.0.9).

## v2.0.8 (2016-12-02)

Adds the [`emplace`](../api/basic_json/emplace.md) and
[`emplace_back`](../api/basic_json/emplace_back.md) functions and improves parsing and serialization
performance. All changes are backward-compatible.
[Full release notes](https://github.com/nlohmann/json/releases/tag/v2.0.8).

## v2.0.7 (2016-11-02)

Fixes several parser bugs found through the "Parsing JSON is a Minefield" study (short files, encoding
detection, surrogate pairs). All changes are backward-compatible.
[Full release notes](https://github.com/nlohmann/json/releases/tag/v2.0.7).

## v2.0.6 (2016-10-15)

Fixes [`operator[]`](../api/basic_json/operator%5B%5D.md) for [JSON pointers](../features/json_pointer.md)
so that it creates missing values like the other overloads. All changes are backward-compatible.
[Full release notes](https://github.com/nlohmann/json/releases/tag/v2.0.6).

## v2.0.5 (2016-09-14)

Fixes a remaining stream end-of-file detection bug in the parser. All changes are backward-compatible.
[Full release notes](https://github.com/nlohmann/json/releases/tag/v2.0.5).

## v2.0.4 (2016-09-11)

Fixes stream end-of-file detection in the parser. All changes are backward-compatible.
[Full release notes](https://github.com/nlohmann/json/releases/tag/v2.0.4).

## v2.0.3 (2016-08-31)

Generalizes the parser to accept any contiguous sequence of one-byte elements and deprecates the
input-stream constructor in favor of the [`parse`](../api/basic_json/parse.md) function. All changes
are backward-compatible. [Full release notes](https://github.com/nlohmann/json/releases/tag/v2.0.3).

## v2.0.2 (2016-07-31)

Overhauls the parser (now rejecting unescaped control characters), tightens the class invariants, and
cleans up the code. All changes are backward-compatible.
[Full release notes](https://github.com/nlohmann/json/releases/tag/v2.0.2).

## v2.0.1 (2016-06-28)

Fixes a performance regression in the [`dump`](../api/basic_json/dump.md) function by adjusting the
stream locale once per serialization. All changes are backward-compatible.
[Full release notes](https://github.com/nlohmann/json/releases/tag/v2.0.1).

## v2.0.0 (2016-06-24)

Feature release with a minor (potentially non-backward-compatible) API change from added `noexcept`
and `constexpr` specifiers.

- Adds [JSON Pointer](../features/json_pointer.md) support in [`at`](../api/basic_json/at.md) and
  [`operator[]`](../api/basic_json/operator%5B%5D.md), plus [`flatten`](../api/basic_json/flatten.md)
  and [`unflatten`](../api/basic_json/unflatten.md).
- Adds [JSON Patch](../features/json_patch.md) via [`diff`](../api/basic_json/diff.md) and
  [`patch`](../api/basic_json/patch.md), unsigned 64-bit integer support, and locale-independent
  serialization.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v2.0.0).

## v1.1.0 (2016-01-24)

Bug-fix and feature release. All changes are backward-compatible.

- Improves floating-point round-tripping, adds a `get_ref` accessor for stored values, and introduces
  runtime [assertions](../features/assertions.md).

[Full release notes](https://github.com/nlohmann/json/releases/tag/v1.1.0).

## v1.0.0 (2015-12-28)

First official release. [Full release notes](https://github.com/nlohmann/json/releases/tag/v1.0.0).

## See also

- [Migration Guide](../integration/migration_guide.md) — how to future-proof your code for the next
  major version and replace deprecated functions.
