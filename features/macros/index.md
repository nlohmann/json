# Supported Macros

Some aspects of the library can be configured by defining preprocessor macros before including the `json.hpp` header. See also the [API documentation for macros](https://json.nlohmann.me/api/macros/index.md) for examples and more information.

## `JSON_ASSERT(x)`

This macro controls which code is executed for [runtime assertions](https://json.nlohmann.me/features/assertions/index.md) of the library.

See [full documentation of `JSON_ASSERT(x)`](https://json.nlohmann.me/api/macros/json_assert/index.md).

## `JSON_BRACE_INIT_COPY_SEMANTICS`

When defined to `1`, single-element brace initialization of a `basic_json` value (e.g., `json j{value};`) is treated as a copy/move of the element rather than wrapping it in a single-element array. The default value is `0`, which preserves the existing behavior.

See [full documentation of `JSON_BRACE_INIT_COPY_SEMANTICS`](https://json.nlohmann.me/api/macros/json_brace_init_copy_semantics/index.md).

## `JSON_CATCH_USER(exception)`

This macro overrides [`catch`](https://en.cppreference.com/w/cpp/language/try_catch) calls inside the library.

See [full documentation of `JSON_CATCH_USER(exception)`](https://json.nlohmann.me/api/macros/json_throw_user/index.md).

## `JSON_DIAGNOSTICS`

This macro enables extended diagnostics for exception messages. Possible values are `1` to enable or `0` to disable (default).

When enabled, exception messages contain a [JSON Pointer](https://json.nlohmann.me/features/json_pointer/index.md) to the JSON value that triggered the exception, see [Extended diagnostic messages](https://json.nlohmann.me/home/exceptions/#extended-diagnostic-messages) for an example. Note that enabling this macro increases the size of every JSON value by one pointer and adds some runtime overhead.

The diagnostics messages can also be controlled with the CMake option [`JSON_Diagnostics`](https://json.nlohmann.me/integration/cmake/#json_diagnostics) (`OFF` by default) which sets `JSON_DIAGNOSTICS` accordingly.

See [full documentation of `JSON_DIAGNOSTICS`](https://json.nlohmann.me/api/macros/json_diagnostics/index.md).

## `JSON_DIAGNOSTIC_POSITIONS`

When enabled, two new member functions [`start_pos()`](https://json.nlohmann.me/api/basic_json/start_pos/index.md) and [`end_pos()`](https://json.nlohmann.me/api/basic_json/end_pos/index.md) are added to [`basic_json`](https://json.nlohmann.me/api/basic_json/index.md) values. If the value was created by calling the[`parse`](https://json.nlohmann.me/api/basic_json/parse/index.md) function, then these functions allow querying the byte positions of the value in the input it was parsed from. The byte positions are also used in exceptions to help locate errors.

The diagnostics positions can also be controlled with the CMake option [`JSON_Diagnostic_Positions`](https://json.nlohmann.me/integration/cmake/#json_diagnostic_positions) (`OFF` by default) which sets `JSON_DIAGNOSTIC_POSITIONS` accordingly.

See [full documentation of `JSON_DIAGNOSTIC_POSITIONS`](https://json.nlohmann.me/api/macros/json_diagnostic_positions/index.md)

## `JSON_HAS_CPP_11`, `JSON_HAS_CPP_14`, `JSON_HAS_CPP_17`, `JSON_HAS_CPP_20`, `JSON_HAS_CPP_23`, `JSON_HAS_CPP_26`

The library targets C++11, but also supports some features introduced in later C++ versions (e.g., `std::string_view` support for C++17). For these new features, the library implements some preprocessor checks to determine the C++ standard. By defining any of these symbols, the internal check is overridden and the provided C++ version is unconditionally assumed. This can be helpful for compilers that only implement parts of the standard and would be detected incorrectly.

See [full documentation of `JSON_HAS_CPP_11`, `JSON_HAS_CPP_14`, `JSON_HAS_CPP_17`, `JSON_HAS_CPP_20`, `JSON_HAS_CPP_23`, and `JSON_HAS_CPP_26`](https://json.nlohmann.me/api/macros/json_has_cpp_11/index.md).

## `JSON_HAS_FILESYSTEM`, `JSON_HAS_EXPERIMENTAL_FILESYSTEM`

When compiling with C++17, the library provides conversions from and to `std::filesystem::path`. As compiler support for filesystem is limited, the library tries to detect whether `<filesystem>`/`std::filesystem` (`JSON_HAS_FILESYSTEM`) or `<experimental/filesystem>`/`std::experimental::filesystem` (`JSON_HAS_EXPERIMENTAL_FILESYSTEM`) should be used. To override the built-in check, define `JSON_HAS_FILESYSTEM` or `JSON_HAS_EXPERIMENTAL_FILESYSTEM` to `1`.

See [full documentation of `JSON_HAS_FILESYSTEM` and `JSON_HAS_EXPERIMENTAL_FILESYSTEM`](https://json.nlohmann.me/api/macros/json_has_filesystem/index.md).

## `JSON_NOEXCEPTION`

Exceptions can be switched off by defining the symbol `JSON_NOEXCEPTION`.

See [full documentation of `JSON_NOEXCEPTION`](https://json.nlohmann.me/api/macros/json_noexception/index.md).

## `JSON_DISABLE_ENUM_SERIALIZATION`

When defined, default parse and serialize functions for enums are excluded and have to be provided by the user, for example, using [`NLOHMANN_JSON_SERIALIZE_ENUM`](https://json.nlohmann.me/api/macros/nlohmann_json_serialize_enum/index.md).

See [full documentation of `JSON_DISABLE_ENUM_SERIALIZATION`](https://json.nlohmann.me/api/macros/json_disable_enum_serialization/index.md).

## `JSON_NO_IO`

When defined, headers `<cstdio>`, `<ios>`, `<iosfwd>`, `<istream>`, and `<ostream>` are not included and parse functions relying on these headers are excluded. This is relevant for environment where these I/O functions are disallowed for security reasons (e.g., Intel Software Guard Extensions (SGX)).

See [full documentation of `JSON_NO_IO`](https://json.nlohmann.me/api/macros/json_no_io/index.md).

## `JSON_SKIP_LIBRARY_VERSION_CHECK`

When defined, the library will not create a compiler warning when a different version of the library was already included.

See [full documentation of `JSON_SKIP_LIBRARY_VERSION_CHECK`](https://json.nlohmann.me/api/macros/json_skip_library_version_check/index.md).

## `JSON_SKIP_UNSUPPORTED_COMPILER_CHECK`

When defined, the library will not create a compile error when a known unsupported compiler is detected. This allows using the library with compilers that do not fully support C++11 and may only work if unsupported features are not used.

See [full documentation of `JSON_SKIP_UNSUPPORTED_COMPILER_CHECK`](https://json.nlohmann.me/api/macros/json_skip_unsupported_compiler_check/index.md).

## `JSON_THROW_USER(exception)`

This macro overrides `throw` calls inside the library. The argument is the exception to be thrown.

See [full documentation of `JSON_THROW_USER(exception)`](https://json.nlohmann.me/api/macros/json_throw_user/index.md).

## `JSON_TRY_USER`

This macro overrides `try` calls inside the library.

See [full documentation of `JSON_TRY_USER`](https://json.nlohmann.me/api/macros/json_throw_user/index.md).

## `JSON_USE_IMPLICIT_CONVERSIONS`

When defined to `0`, implicit conversions are switched off. By default, implicit conversions are switched on.

See [full documentation of `JSON_USE_IMPLICIT_CONVERSIONS`](https://json.nlohmann.me/api/macros/json_use_implicit_conversions/index.md).

## `JSON_USE_GLOBAL_UDLS`

When defined to `1` (default), the user-defined string literals `operator""_json` and `operator""_json_pointer` are placed into the global namespace instead of `nlohmann::literals::json_literals`.

See [full documentation of `JSON_USE_GLOBAL_UDLS`](https://json.nlohmann.me/api/macros/json_use_global_udls/index.md).

## `JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON`

When defined to `1`, the library restores the legacy behavior in which a discarded value compared equal to itself. This behavior is deprecated and switched off (`0`) by default.

See [full documentation of `JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON`](https://json.nlohmann.me/api/macros/json_use_legacy_discarded_value_comparison/index.md).

## `NLOHMANN_DEFINE_TYPE_*(...)`, `NLOHMANN_DEFINE_DERIVED_TYPE_*(...)`

The library defines 12 macros to simplify the serialization/deserialization of types. See the page on [arbitrary type conversion](https://json.nlohmann.me/features/arbitrary_types/#simplify-your-life-with-macros) for a detailed discussion.

## `NLOHMANN_JSON_NAMESPACE`, `NLOHMANN_JSON_NAMESPACE_BEGIN`, `NLOHMANN_JSON_NAMESPACE_END`, `NLOHMANN_JSON_NAMESPACE_NO_VERSION`

These macros relate to the versioned, inline `nlohmann` namespace:

- `NLOHMANN_JSON_NAMESPACE` evaluates to the full name of the `nlohmann` namespace (including the inline ABI namespace).
- `NLOHMANN_JSON_NAMESPACE_BEGIN` / `NLOHMANN_JSON_NAMESPACE_END` open and close the namespace (for example, to add specializations).
- `NLOHMANN_JSON_NAMESPACE_NO_VERSION`, when defined to `1`, omits the version component from the inline namespace.

See the [`nlohmann` Namespace](https://json.nlohmann.me/features/namespace/index.md) page, and the full documentation of [`NLOHMANN_JSON_NAMESPACE`](https://json.nlohmann.me/api/macros/nlohmann_json_namespace/index.md), [`NLOHMANN_JSON_NAMESPACE_BEGIN` / `NLOHMANN_JSON_NAMESPACE_END`](https://json.nlohmann.me/api/macros/nlohmann_json_namespace_begin/index.md), and [`NLOHMANN_JSON_NAMESPACE_NO_VERSION`](https://json.nlohmann.me/api/macros/nlohmann_json_namespace_no_version/index.md).

## `NLOHMANN_JSON_SERIALIZE_ENUM(type, ...)`

This macro simplifies the serialization/deserialization of enum types. See [Specializing enum conversion](https://json.nlohmann.me/features/enum_conversion/index.md) for more information.

See [full documentation of `NLOHMANN_JSON_SERIALIZE_ENUM`](https://json.nlohmann.me/api/macros/nlohmann_json_serialize_enum/index.md).

A strict variant [`NLOHMANN_JSON_SERIALIZE_ENUM_STRICT`](https://json.nlohmann.me/api/macros/nlohmann_json_serialize_enum_strict/index.md) throws an exception on undefined input instead of falling back to the first mapping.

## `NLOHMANN_JSON_VERSION_MAJOR`, `NLOHMANN_JSON_VERSION_MINOR`, `NLOHMANN_JSON_VERSION_PATCH`

These macros are defined by the library and contain the version numbers according to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

See [full documentation of `NLOHMANN_JSON_VERSION_MAJOR`, `NLOHMANN_JSON_VERSION_MINOR`, and `NLOHMANN_JSON_VERSION_PATCH`](https://json.nlohmann.me/api/macros/nlohmann_json_version_major/index.md).
