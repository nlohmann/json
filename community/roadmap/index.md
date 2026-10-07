# Roadmap

This page describes what the project intends to do, and what it does not intend to do, over the next year. Concrete work items are tracked in the [GitHub milestones](https://github.com/nlohmann/json/milestones) and the [issue tracker](https://github.com/nlohmann/json/issues).

## What the project will do

- **Keep the C++11 baseline.** The library will continue to compile with every [supported C++11 compiler](https://github.com/nlohmann/json/blob/develop/README.md#supported-compilers). Features of later standards are only used when they are guarded by the `JSON_HAS_CPP_*` macros.
- **Stay conformant to JSON.** The parser and serializer follow [RFC 8259](https://datatracker.ietf.org/doc/html/rfc8259). Extensions such as [comments](https://json.nlohmann.me/features/comments/index.md) or [trailing commas](https://json.nlohmann.me/features/trailing_commas/index.md) remain opt-in.
- **Keep the 3.x public API stable.** Releases follow [semantic versioning](https://semver.org). Changes that would break existing code are only added behind a feature macro, so users can opt in and test their code before a next major release, see [Version 4.0](#version-40).
- **Support a broad range of compilers and platforms.** The [CI](https://json.nlohmann.me/community/quality_assurance/index.md) keeps testing old and new versions of GCC, Clang, MSVC, and other compilers on Linux, macOS, and Windows.
- **Keep the quality assurance up.** Every change keeps the test coverage at 100%, passes the static and dynamic analysis, and is fuzz-tested by OSS-Fuzz, see [Quality assurance](https://json.nlohmann.me/community/quality_assurance/index.md).
- **Harden the library against hostile input.** Handling deeply nested values without exhausting the call stack is ongoing work.
- **Fix bugs and security issues** reported through the issue tracker and the [security policy](https://json.nlohmann.me/community/security_policy/index.md).

## What the project will not do

- **Break the public API of version 3.x.** See [API stability](#api-stability) for what this covers.
- **Require a newer C++ standard than C++11.**
- **Break JSON conformance** or enable non-standard extensions by default.
- **Add dependencies** or require a build step. The library remains header-only, and the single header `json.hpp` remains a complete distribution.
- **Trade simplicity for speed or memory efficiency.** Performance improvements are welcome, but the library is not meant to compete with the fastest JSON libraries, see [Design goals](https://json.nlohmann.me/home/design_goals/index.md).

## API stability

Releases follow [semantic versioning](https://semver.org): a minor or patch release of version 3.x does not break code that uses the public API. In particular, a 3.x release does not:

- change the signature of a function (its parameter types, return type, number of parameters, or the const-ness of a member function);
- remove or rename a function or class;
- change which exceptions a function throws, or the [exception ids](https://json.nlohmann.me/home/exceptions/index.md);
- change access specifiers or default arguments.

Exceptions to these rules, for instance when fixing a bug requires changing the exception a function throws, are documented in the [release notes](https://json.nlohmann.me/home/releases/index.md).

The following are **not** part of the public API and may change in any release, including patch releases:

- The text of exception messages returned by `what()`. Use the [exception id](https://json.nlohmann.me/home/exceptions/index.md) to tell errors apart.
- The ABI, including `sizeof(basic_json)` and the memory layout of its values. Recompile your code when you upgrade the library. The [versioned inline namespace](https://json.nlohmann.me/features/namespace/index.md) turns mixing versions into a link error.
- Everything in namespace `nlohmann::detail`, and macros and type traits that are not documented in the [API reference](https://json.nlohmann.me/api/basic_json/index.md).

Changes that would break the public API are only added behind a macro whose default keeps the 3.x behavior, see [Version 4.0](#version-40).

## Version 4.0

There is no release date for version 4.0 yet. Proposals that need a major version, for instance stricter type conversions, are collected in issue [#3453](https://github.com/nlohmann/json/issues/3453).

Not final

The plan for version 4.0 described below is not final and may still change: macros may be added to or removed from the list, and planned defaults may be revised. Any such change will be documented on this page.

### Trying out 4.0 today

Version 4.0 will not be developed on a separate branch. Instead, every breaking change is first added to a 3.x release behind a macro whose default keeps the 3.x behavior. Version 4.0 then switches the defaults and removes the macros. Version 4.0 is therefore the sum of these macros: you can try it on the 3.x release train today by defining each macro to its 4.0 value and fixing what no longer compiles or behaves differently. Once your code works with all of them, it is ready for version 4.0.

The following macros guard changes that are planned to become the default in version 4.0:

| Macro                                                                                                                                   | 3.x default | 4.0 behavior                                                                                                                             | CMake option                                                                                                               | Added  |
| --------------------------------------------------------------------------------------------------------------------------------------- | ----------- | ---------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | ------ |
| [`JSON_USE_IMPLICIT_CONVERSIONS`](https://json.nlohmann.me/api/macros/json_use_implicit_conversions/index.md)                           | `1`         | `0`: no implicit conversions from `basic_json` to other types; use [`get`](https://json.nlohmann.me/api/basic_json/get/index.md) instead | [`JSON_ImplicitConversions`](https://json.nlohmann.me/integration/cmake/#json_implicitconversions)                         | 3.9.0  |
| [`JSON_USE_GLOBAL_UDLS`](https://json.nlohmann.me/api/macros/json_use_global_udls/index.md)                                             | `1`         | `0`: the string literals `_json` and `_json_pointer` are only available in namespace `nlohmann::literals`                                | [`JSON_GlobalUDLs`](https://json.nlohmann.me/integration/cmake/#json_globaludls)                                           | 3.11.0 |
| [`JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON`](https://json.nlohmann.me/api/macros/json_use_legacy_discarded_value_comparison/index.md) | `0`         | removed: the deprecated legacy comparison of discarded values can no longer be enabled                                                   | [`JSON_LegacyDiscardedValueComparison`](https://json.nlohmann.me/integration/cmake/#json_legacydiscardedvaluecomparison)   | 3.11.0 |
| [`JSON_BRACE_INIT_COPY_SEMANTICS`](https://json.nlohmann.me/api/macros/json_brace_init_copy_semantics/index.md)                         | `0`         | `1`: single-element brace initialization such as `json j{obj};` copies the element instead of creating an array                          | –                                                                                                                          | 3.13.0 |
| [`JSON_PRECISE_STREAM_POSITION`](https://json.nlohmann.me/api/macros/json_precise_stream_position/index.md)                             | `0`         | `1`: reading from a stream does not consume the character after a number                                                                 | –                                                                                                                          | 3.13.0 |
| [`JSON_STRICT_NUL_HANDLING`](https://json.nlohmann.me/api/macros/json_strict_nul_handling/index.md)                                     | `0`         | `1`: a NUL byte in the input is a parse error instead of the end of input                                                                | [`JSON_StrictNulHandling`](https://json.nlohmann.me/integration/cmake/#json_strictnulhandling)                             | 3.13.0 |
| [`JSON_STRICT_BINARY_UTF8`](https://json.nlohmann.me/api/macros/json_strict_binary_utf8/index.md)                                       | `0`         | `1`: `to_cbor`, `to_ubjson`, `to_bjdata`, and `to_bson` throw for strings that are not valid UTF-8 by default                            | [`JSON_StrictBinaryUTF8`](https://json.nlohmann.me/integration/cmake/#json_strictbinaryutf8)                               | 3.13.0 |
| [`JSON_DISABLE_TUPLE_REFERENCE_CONVERSION`](https://json.nlohmann.me/api/macros/json_disable_tuple_reference_conversion/index.md)       | `0`         | `1`: a `basic_json` value can no longer be created from a one-element tuple of a reference to it, such as `std::forward_as_tuple(j)`     | [`JSON_DisableTupleReferenceConversion`](https://json.nlohmann.me/integration/cmake/#json_disabletuplereferenceconversion) | 3.13.0 |
| [`JSON_DELETE_DEPRECATED_FUNCTIONS`](https://json.nlohmann.me/api/macros/json_delete_deprecated_functions/index.md)                     | `0`         | removed: the deprecated functions are removed (see below); the `from_*(ptr, len)` overloads stay deleted                                 | [`JSON_DeleteDeprecatedFunctions`](https://json.nlohmann.me/integration/cmake/#json_deletedeprecatedfunctions)             | 3.13.0 |

For example, the following makes a 3.x release behave like version 4.0 with respect to these changes:

```
#define JSON_USE_IMPLICIT_CONVERSIONS 0
#define JSON_USE_GLOBAL_UDLS 0
#define JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON 0
#define JSON_BRACE_INIT_COPY_SEMANTICS 1
#define JSON_PRECISE_STREAM_POSITION 1
#define JSON_STRICT_NUL_HANDLING 1
#define JSON_STRICT_BINARY_UTF8 1
#define JSON_DISABLE_TUPLE_REFERENCE_CONVERSION 1
#define JSON_DELETE_DEPRECATED_FUNCTIONS 1
#include <nlohmann/json.hpp>
```

The macros must be defined before the library header is included; setting them once in the build system is the easiest way to achieve this.

### Removal of deprecated functions

Version 4.0 will remove all deprecated functions. Compiling with deprecation warnings enabled shows which of them your code still uses. Defining [`JSON_DELETE_DEPRECATED_FUNCTIONS`](https://json.nlohmann.me/api/macros/json_delete_deprecated_functions/index.md) to `1` turns these warnings into errors, as the deprecated functions are then deleted. The [migration guide](https://json.nlohmann.me/integration/migration_guide/#replace-deprecated-functions) shows how to replace each of them.

The `from_*` overloads taking a pointer and a length are not removed in version 4.0, but stay deleted. Without them, a call like `from_cbor(ptr, len)` would still compile: it would read `ptr` as a NUL-terminated string and convert `len` to the `strict` parameter.

| Deprecated                                                                                                                                                                                                                                                                                                                                                        | Since  | Migration                                                                                                |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ | -------------------------------------------------------------------------------------------------------- |
| `operator<<(basic_json&, std::istream&)`                                                                                                                                                                                                                                                                                                                          | 3.0.0  | [Parsing](https://json.nlohmann.me/integration/migration_guide/#parsing)                                 |
| `operator>>(const basic_json&, std::ostream&)`                                                                                                                                                                                                                                                                                                                    | 3.0.0  | [Miscellaneous functions](https://json.nlohmann.me/integration/migration_guide/#miscellaneous-functions) |
| `iterator_wrapper`                                                                                                                                                                                                                                                                                                                                                | 3.1.0  | [Miscellaneous functions](https://json.nlohmann.me/integration/migration_guide/#miscellaneous-functions) |
| [`parse`](https://json.nlohmann.me/api/basic_json/parse/index.md), [`accept`](https://json.nlohmann.me/api/basic_json/accept/index.md), and [`sax_parse`](https://json.nlohmann.me/api/basic_json/sax_parse/index.md) with an initializer list `{ptr, len}` or `{first, last}`                                                                                    | 3.8.0  | [Parsing](https://json.nlohmann.me/integration/migration_guide/#parsing)                                 |
| [`from_bson`](https://json.nlohmann.me/api/basic_json/from_bson/index.md), [`from_cbor`](https://json.nlohmann.me/api/basic_json/from_cbor/index.md), [`from_msgpack`](https://json.nlohmann.me/api/basic_json/from_msgpack/index.md), and [`from_ubjson`](https://json.nlohmann.me/api/basic_json/from_ubjson/index.md) with `(ptr, len)` or an initializer list | 3.8.0  | [Parsing](https://json.nlohmann.me/integration/migration_guide/#parsing)                                 |
| [`json_pointer::operator string_t`](https://json.nlohmann.me/api/json_pointer/operator_string_t/index.md)                                                                                                                                                                                                                                                         | 3.11.0 | [JSON Pointers](https://json.nlohmann.me/integration/migration_guide/#json-pointers)                     |
| [`json_pointer`](https://json.nlohmann.me/api/json_pointer/index.md) with a `basic_json` type as template argument, and the overloads of `value`, `contains`, `operator[]`, and `at` accepting such a pointer                                                                                                                                                     | 3.11.0 | [JSON Pointers](https://json.nlohmann.me/integration/migration_guide/#json-pointers)                     |
| Comparing a [`json_pointer`](https://json.nlohmann.me/api/json_pointer/index.md) with a string via [`operator==`](https://json.nlohmann.me/api/json_pointer/operator_eq/index.md) or [`operator!=`](https://json.nlohmann.me/api/json_pointer/operator_ne/index.md)                                                                                               | 3.11.2 | [JSON Pointers](https://json.nlohmann.me/integration/migration_guide/#json-pointers)                     |
| [`from_bjdata`](https://json.nlohmann.me/api/basic_json/from_bjdata/index.md) and [`from_bon8`](https://json.nlohmann.me/api/basic_json/from_bon8/index.md) with `(ptr, len)`                                                                                                                                                                                     | 3.13.0 | [Parsing](https://json.nlohmann.me/integration/migration_guide/#parsing)                                 |

The deprecated legacy comparison of discarded values is controlled by a macro and therefore listed in the table above.

New breaking changes will follow the same path: they are added to these tables when they land in a 3.x release.
