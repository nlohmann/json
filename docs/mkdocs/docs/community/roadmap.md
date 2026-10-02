# Roadmap

This page describes what the project intends to do, and what it does not intend to do, over the next year. Concrete
work items are tracked in the [GitHub milestones](https://github.com/nlohmann/json/milestones) and the
[issue tracker](https://github.com/nlohmann/json/issues).

## What the project will do

- **Keep the C++11 baseline.** The library will continue to compile with every
  [supported C++11 compiler](https://github.com/nlohmann/json/blob/develop/README.md#supported-compilers). Features of
  later standards are only used when they are guarded by the `JSON_HAS_CPP_*` macros.
- **Stay conformant to JSON.** The parser and serializer follow [RFC 8259](https://datatracker.ietf.org/doc/html/rfc8259).
  Extensions such as [comments](../features/comments.md) or [trailing commas](../features/trailing_commas.md) remain
  opt-in.
- **Keep the 3.x public API stable.** Releases follow [semantic versioning](https://semver.org). Changes that would
  break existing code are only added behind a feature macro, so users can opt in and test their code before a next
  major release, see [Version 4.0](#version-40).
- **Support a broad range of compilers and platforms.** The [CI](quality_assurance.md) keeps testing old and new
  versions of GCC, Clang, MSVC, and other compilers on Linux, macOS, and Windows.
- **Keep the quality assurance up.** Every change keeps the test coverage at 100%, passes the static and dynamic
  analysis, and is fuzz-tested by OSS-Fuzz, see [Quality assurance](quality_assurance.md).
- **Harden the library against hostile input.** Handling deeply nested values without exhausting the call stack is
  ongoing work.
- **Fix bugs and security issues** reported through the issue tracker and the [security policy](security_policy.md).

## What the project will not do

- **Break the public API of version 3.x.** See the
  [contribution guidelines](https://github.com/nlohmann/json/blob/develop/.github/CONTRIBUTING.md#break-the-public-api)
  for what counts as a breaking change.
- **Require a newer C++ standard than C++11.**
- **Break JSON conformance** or enable non-standard extensions by default.
- **Add dependencies** or require a build step. The library remains header-only, and the single header
  `json.hpp` remains a complete distribution.
- **Trade simplicity for speed or memory efficiency.** Performance improvements are welcome, but the library is not
  meant to compete with the fastest JSON libraries, see [Design goals](../home/design_goals.md).

## Version 4.0

There is no release date for version 4.0 yet. Proposals that need a major version, for instance stricter type
conversions, are collected in issue [#3453](https://github.com/nlohmann/json/issues/3453).

!!! note "Not final"

    The plan for version 4.0 described below is not final and may still change: macros may be added to or removed from
    the list, and planned defaults may be revised. Any such change will be documented on this page.

### Trying out 4.0 today

Version 4.0 will not be developed on a separate branch. Instead, every breaking change is first added to a 3.x release
behind a macro whose default keeps the 3.x behavior. Version 4.0 then switches the defaults and removes the macros.
Version 4.0 is therefore the sum of these macros: you can try it on the 3.x release train today by defining each macro
to its 4.0 value and fixing what no longer compiles or behaves differently. Once your code works with all of them, it
is ready for version 4.0.

The following macros guard changes that are planned to become the default in version 4.0:

| Macro                                                                                                            | 3.x default | 4.0 behavior                                                                                                                  | CMake option                                                                                                       | Added  |
|------------------------------------------------------------------------------------------------------------------|-------------|-------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------|--------|
| [`JSON_USE_IMPLICIT_CONVERSIONS`](../api/macros/json_use_implicit_conversions.md)                                | `1`         | `0`: no implicit conversions from `basic_json` to other types; use [`get`](../api/basic_json/get.md) instead                  | [`JSON_ImplicitConversions`](../integration/cmake.md#json_implicitconversions)                                     | 3.9.0  |
| [`JSON_USE_GLOBAL_UDLS`](../api/macros/json_use_global_udls.md)                                                  | `1`         | `0`: the string literals `_json` and `_json_pointer` are only available in namespace `nlohmann::literals`                    | [`JSON_GlobalUDLs`](../integration/cmake.md#json_globaludls)                                                       | 3.11.0 |
| [`JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON`](../api/macros/json_use_legacy_discarded_value_comparison.md)      | `0`         | removed: the deprecated legacy comparison of discarded values can no longer be enabled                                        | [`JSON_LegacyDiscardedValueComparison`](../integration/cmake.md#json_legacydiscardedvaluecomparison)               | 3.11.0 |
| [`JSON_BRACE_INIT_COPY_SEMANTICS`](../api/macros/json_brace_init_copy_semantics.md)                              | `0`         | `1`: single-element brace initialization such as `#!cpp json j{obj};` copies the element instead of creating an array         | –                                                                                                                  | 3.13.0 |
| [`JSON_PRECISE_STREAM_POSITION`](../api/macros/json_precise_stream_position.md)                                  | `0`         | `1`: reading from a stream does not consume the character after a number                                                      | –                                                                                                                  | 3.13.0 |
| [`JSON_STRICT_NUL_HANDLING`](../api/macros/json_strict_nul_handling.md)                                          | `0`         | `1`: a NUL byte in the input is a parse error instead of the end of input                                                     | [`JSON_StrictNulHandling`](../integration/cmake.md#json_strictnulhandling)                                         | 3.13.0 |
| [`JSON_STRICT_BINARY_UTF8`](../api/macros/json_strict_binary_utf8.md)                                            | `0`         | `1`: `to_cbor`, `to_ubjson`, `to_bjdata`, and `to_bson` throw for strings that are not valid UTF-8 by default                 | [`JSON_StrictBinaryUTF8`](../integration/cmake.md#json_strictbinaryutf8)                                           | 3.13.0 |

For example, the following makes a 3.x release behave like version 4.0 with respect to these changes:

```cpp
#define JSON_USE_IMPLICIT_CONVERSIONS 0
#define JSON_USE_GLOBAL_UDLS 0
#define JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON 0
#define JSON_BRACE_INIT_COPY_SEMANTICS 1
#define JSON_PRECISE_STREAM_POSITION 1
#define JSON_STRICT_NUL_HANDLING 1
#define JSON_STRICT_BINARY_UTF8 1
#include <nlohmann/json.hpp>
```

The macros must be defined before the library header is included; setting them once in the build system is the easiest
way to achieve this.

### Removal of deprecated functions

Version 4.0 will remove all deprecated functions. Compiling with deprecation warnings enabled shows which of them your
code still uses. The [migration guide](../integration/migration_guide.md#replace-deprecated-functions) shows how to
replace each of them.

| Deprecated                                                                                                                                                                                                                                         | Since  | Migration                                                                        |
|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------|----------------------------------------------------------------------------------|
| `#!cpp operator<<(basic_json&, std::istream&)`                                                                                                                                                                                                     | 3.0.0  | [Parsing](../integration/migration_guide.md#parsing)                             |
| `#!cpp operator>>(const basic_json&, std::ostream&)`                                                                                                                                                                                               | 3.0.0  | [Miscellaneous functions](../integration/migration_guide.md#miscellaneous-functions) |
| `iterator_wrapper`                                                                                                                                                                                                                                 | 3.1.0  | [Miscellaneous functions](../integration/migration_guide.md#miscellaneous-functions) |
| [`parse`](../api/basic_json/parse.md), [`accept`](../api/basic_json/accept.md), and [`sax_parse`](../api/basic_json/sax_parse.md) with an initializer list `{ptr, len}` or `{first, last}`                                                         | 3.8.0  | [Parsing](../integration/migration_guide.md#parsing)                             |
| [`from_bson`](../api/basic_json/from_bson.md), [`from_cbor`](../api/basic_json/from_cbor.md), [`from_msgpack`](../api/basic_json/from_msgpack.md), and [`from_ubjson`](../api/basic_json/from_ubjson.md) with `(ptr, len)` or an initializer list | 3.8.0  | [Parsing](../integration/migration_guide.md#parsing)                             |
| [`json_pointer::operator string_t`](../api/json_pointer/operator_string_t.md)                                                                                                                                                                      | 3.11.0 | [JSON Pointers](../integration/migration_guide.md#json-pointers)                 |
| [`json_pointer`](../api/json_pointer/index.md) with a `basic_json` type as template argument, and the overloads of `value`, `contains`, `operator[]`, and `at` accepting such a pointer                                                           | 3.11.0 | [JSON Pointers](../integration/migration_guide.md#json-pointers)                 |
| Comparing a [`json_pointer`](../api/json_pointer/index.md) with a string via [`operator==`](../api/json_pointer/operator_eq.md) or [`operator!=`](../api/json_pointer/operator_ne.md)                                                              | 3.11.2 | [JSON Pointers](../integration/migration_guide.md#json-pointers)                 |

The deprecated legacy comparison of discarded values is controlled by a macro and therefore listed in the table above.

New breaking changes will follow the same path: they are added to these tables when they land in a 3.x release.
