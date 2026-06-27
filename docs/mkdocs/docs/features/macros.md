# Supported Macros

Some aspects of the library can be configured by defining preprocessor macros before including the `json.hpp` header.
See also the [API documentation for macros](../api/macros/index.md) for examples and more information.

## `JSON_ASSERT(x)`

This macro controls which code is executed for [runtime assertions](assertions.md) of the library.

See [full documentation of `JSON_ASSERT(x)`](../api/macros/json_assert.md).

## `JSON_BRACE_INIT_COPY_SEMANTICS`

When defined to `1`, single-element brace initialization of a `basic_json` value (e.g., `#!cpp json j{value};`) is
treated as a copy/move of the element rather than wrapping it in a single-element array. The default value is `0`, which
preserves the existing behavior.

See [full documentation of `JSON_BRACE_INIT_COPY_SEMANTICS`](../api/macros/json_brace_init_copy_semantics.md).

## `JSON_CATCH_USER(exception)`

This macro overrides [`#!cpp catch`](https://en.cppreference.com/w/cpp/language/try_catch) calls inside the library.

See [full documentation of `JSON_CATCH_USER(exception)`](../api/macros/json_throw_user.md).

## `JSON_DIAGNOSTICS`

This macro enables extended diagnostics for exception messages. Possible values are `1` to enable or `0` to disable
(default).

When enabled, exception messages contain a [JSON Pointer](json_pointer.md) to the JSON value that triggered the
exception, see [Extended diagnostic messages](../home/exceptions.md#extended-diagnostic-messages) for an example. Note
that enabling this macro increases the size of every JSON value by one pointer and adds some runtime overhead.

The diagnostics messages can also be controlled with the CMake option
[`JSON_Diagnostics`](../integration/cmake.md#json_diagnostics) (`OFF` by default) which sets `JSON_DIAGNOSTICS`
accordingly.

See [full documentation of `JSON_DIAGNOSTICS`](../api/macros/json_diagnostics.md).

## `JSON_DIAGNOSTIC_POSITIONS`

When enabled, two new member functions [`start_pos()`](../api/basic_json/start_pos.md) and
[`end_pos()`](../api/basic_json/end_pos.md) are added to [`basic_json`](../api/basic_json/index.md) values. If the value
was created by calling the[`parse`](../api/basic_json/parse.md) function, then these functions allow querying the byte
positions of the value in the input it was parsed from. The byte positions are also used in exceptions to help locate
errors.

The diagnostics positions can also be controlled with the CMake option
[`JSON_Diagnostic_Positions`](../integration/cmake.md#json_diagnostic_positions) (`OFF` by default) which sets
`JSON_DIAGNOSTIC_POSITIONS` accordingly.

See [full documentation of `JSON_DIAGNOSTIC_POSITIONS`](../api/macros/json_diagnostic_positions.md)

## `JSON_HAS_CPP_11`, `JSON_HAS_CPP_14`, `JSON_HAS_CPP_17`, `JSON_HAS_CPP_20`, `JSON_HAS_CPP_23`, `JSON_HAS_CPP_26`

The library targets C++11, but also supports some features introduced in later C++ versions (e.g., `std::string_view`
support for C++17). For these new features, the library implements some preprocessor checks to determine the C++
standard. By defining any of these symbols, the internal check is overridden and the provided C++ version is
unconditionally assumed. This can be helpful for compilers that only implement parts of the standard and would be
detected incorrectly.

See [full documentation of `JSON_HAS_CPP_11`, `JSON_HAS_CPP_14`, `JSON_HAS_CPP_17`, `JSON_HAS_CPP_20`, `JSON_HAS_CPP_23`, and `JSON_HAS_CPP_26`](../api/macros/json_has_cpp_11.md).

## `JSON_HAS_FILESYSTEM`, `JSON_HAS_EXPERIMENTAL_FILESYSTEM`

When compiling with C++17, the library provides conversions from and to `std::filesystem::path`. As compiler support
for filesystem is limited, the library tries to detect whether `<filesystem>`/`std::filesystem` (`JSON_HAS_FILESYSTEM`)
or `<experimental/filesystem>`/`std::experimental::filesystem` (`JSON_HAS_EXPERIMENTAL_FILESYSTEM`) should be used.
To override the built-in check, define `JSON_HAS_FILESYSTEM` or `JSON_HAS_EXPERIMENTAL_FILESYSTEM` to `1`.

See [full documentation of `JSON_HAS_FILESYSTEM` and `JSON_HAS_EXPERIMENTAL_FILESYSTEM`](../api/macros/json_has_filesystem.md).

## `JSON_NOEXCEPTION`

Exceptions can be switched off by defining the symbol `JSON_NOEXCEPTION`.

See [full documentation of `JSON_NOEXCEPTION`](../api/macros/json_noexception.md).

## `JSON_DISABLE_ENUM_SERIALIZATION`

When defined, default parse and serialize functions for enums are excluded and have to be provided by the user, for example, using [`NLOHMANN_JSON_SERIALIZE_ENUM`](../api/macros/nlohmann_json_serialize_enum.md).

See [full documentation of `JSON_DISABLE_ENUM_SERIALIZATION`](../api/macros/json_disable_enum_serialization.md).

## `JSON_NO_IO`

When defined, headers `<cstdio>`, `<ios>`, `<iosfwd>`, `<istream>`, and `<ostream>` are not included and parse functions
relying on these headers are excluded. This is relevant for environment where these I/O functions are disallowed for
security reasons (e.g., Intel Software Guard Extensions (SGX)).

See [full documentation of `JSON_NO_IO`](../api/macros/json_no_io.md).

## `JSON_SKIP_LIBRARY_VERSION_CHECK`

When defined, the library will not create a compiler warning when a different version of the library was already
included.

See [full documentation of `JSON_SKIP_LIBRARY_VERSION_CHECK`](../api/macros/json_skip_library_version_check.md).

## `JSON_SKIP_UNSUPPORTED_COMPILER_CHECK`

When defined, the library will not create a compile error when a known unsupported compiler is detected. This allows 
using the library with compilers that do not fully support C++11 and may only work if unsupported features are not used.

See [full documentation of `JSON_SKIP_UNSUPPORTED_COMPILER_CHECK`](../api/macros/json_skip_unsupported_compiler_check.md).

## `JSON_THROW_USER(exception)`

This macro overrides `#!cpp throw` calls inside the library. The argument is the exception to be thrown.

See [full documentation of `JSON_THROW_USER(exception)`](../api/macros/json_throw_user.md).

## `JSON_TRY_USER`

This macro overrides `#!cpp try` calls inside the library.

See [full documentation of `JSON_TRY_USER`](../api/macros/json_throw_user.md).

## `JSON_USE_IMPLICIT_CONVERSIONS`

When defined to `0`, implicit conversions are switched off. By default, implicit conversions are switched on.

See [full documentation of `JSON_USE_IMPLICIT_CONVERSIONS`](../api/macros/json_use_implicit_conversions.md).

## `JSON_USE_GLOBAL_UDLS`

When defined to `1` (default), the user-defined string literals `operator""_json` and `operator""_json_pointer` are
placed into the global namespace instead of `nlohmann::literals::json_literals`.

See [full documentation of `JSON_USE_GLOBAL_UDLS`](../api/macros/json_use_global_udls.md).

## `JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON`

When defined to `1`, the library restores the legacy behavior in which a discarded value compared equal to itself. This
behavior is deprecated and switched off (`0`) by default.

See [full documentation of `JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON`](../api/macros/json_use_legacy_discarded_value_comparison.md).

## `NLOHMANN_DEFINE_TYPE_*(...)`, `NLOHMANN_DEFINE_DERIVED_TYPE_*(...)`

The library defines 12 macros to simplify the serialization/deserialization of types. See the page on
[arbitrary type conversion](arbitrary_types.md#simplify-your-life-with-macros) for a detailed discussion.

## `NLOHMANN_JSON_NAMESPACE`, `NLOHMANN_JSON_NAMESPACE_BEGIN`, `NLOHMANN_JSON_NAMESPACE_END`, `NLOHMANN_JSON_NAMESPACE_NO_VERSION`

These macros relate to the versioned, inline `nlohmann` namespace:

- `NLOHMANN_JSON_NAMESPACE` evaluates to the full name of the `nlohmann` namespace (including the inline ABI namespace).
- `NLOHMANN_JSON_NAMESPACE_BEGIN` / `NLOHMANN_JSON_NAMESPACE_END` open and close the namespace (for example, to add
  specializations).
- `NLOHMANN_JSON_NAMESPACE_NO_VERSION`, when defined to `1`, omits the version component from the inline namespace.

See the [`nlohmann` Namespace](namespace.md) page, and the full documentation of
[`NLOHMANN_JSON_NAMESPACE`](../api/macros/nlohmann_json_namespace.md),
[`NLOHMANN_JSON_NAMESPACE_BEGIN` / `NLOHMANN_JSON_NAMESPACE_END`](../api/macros/nlohmann_json_namespace_begin.md), and
[`NLOHMANN_JSON_NAMESPACE_NO_VERSION`](../api/macros/nlohmann_json_namespace_no_version.md).

## `NLOHMANN_JSON_SERIALIZE_ENUM(type, ...)`

This macro simplifies the serialization/deserialization of enum types. See
[Specializing enum conversion](enum_conversion.md) for more information.

See [full documentation of `NLOHMANN_JSON_SERIALIZE_ENUM`](../api/macros/nlohmann_json_serialize_enum.md).

A strict variant [`NLOHMANN_JSON_SERIALIZE_ENUM_STRICT`](../api/macros/nlohmann_json_serialize_enum_strict.md) throws an
exception on undefined input instead of falling back to the first mapping.

## `NLOHMANN_JSON_VERSION_MAJOR`, `NLOHMANN_JSON_VERSION_MINOR`, `NLOHMANN_JSON_VERSION_PATCH`

These macros are defined by the library and contain the version numbers according to
[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

See [full documentation of `NLOHMANN_JSON_VERSION_MAJOR`, `NLOHMANN_JSON_VERSION_MINOR`, and `NLOHMANN_JSON_VERSION_PATCH`](../api/macros/nlohmann_json_version_major.md).
