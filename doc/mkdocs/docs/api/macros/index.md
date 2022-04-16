# Macros

!!! note

    This page is under construction. See the [macro overview page](../../features/macros.md) until then.

Some aspects of the library can be configured by defining preprocessor macros **before** including the `json.hpp`
header.

## Runtime assertions

- [**JSON_ASSERT(x)**](json_assert.md) - control behavior of runtime assertions

## Exceptions

- `JSON_CATCH_USER(exception)`
- [**JSON_DIAGNOSTICS**](json_diagnostics.md) - control extended diagnostics
- `JSON_NOEXCEPTION`
- `JSON_THROW_USER(exception)`
- `JSON_TRY_USER`

## Language support

- `JSON_HAS_CPP_11`, `JSON_HAS_CPP_14`, `JSON_HAS_CPP_17`, `JSON_HAS_CPP_20`
- [**JSON_HAS_FILESYSTEM**/**JSON_HAS_EXPERIMENTAL_FILESYSTEM**](json_has_filesystem.md) - control `std::filesystem` support
- `JSON_NO_IO`
- [**JSON_SKIP_UNSUPPORTED_COMPILER_CHECK**](json_skip_unsupported_compiler_check.md) - do not warn about unsupported compilers
- `JSON_SKIP_LIBRARY_VERSION_CHECK`

## Type conversions

- `JSON_USE_IMPLICIT_CONVERSIONS`

## Serialization/deserialization macros

- `NLOHMANN_DEFINE_TYPE_INTRUSIVE(type, member...)`
- `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(type, member...)`
- `NLOHMANN_JSON_SERIALIZE_ENUM(type, ...)`
- `NLOHMANN_JSON_VERSION_MAJOR`, `NLOHMANN_JSON_VERSION_MINOR`, `NLOHMANN_JSON_VERSION_PATCH`
