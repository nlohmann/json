# Macros

Some aspects of the library can be configured by defining preprocessor macros before including the `json.hpp` header.

- [`JSON_ASSERT(x)`](json_assert.md)
- `JSON_CATCH_USER(exception)`
- `JSON_DIAGNOSTICS`
- `JSON_HAS_CPP_11`, `JSON_HAS_CPP_14`, `JSON_HAS_CPP_17`, `JSON_HAS_CPP_20`
- `JSON_NOEXCEPTION`
- `JSON_NO_IO`
- `JSON_SKIP_UNSUPPORTED_COMPILER_CHECK`
- `JSON_THROW_USER(exception)`
- `JSON_TRY_USER`
- `JSON_USE_IMPLICIT_CONVERSIONS`
- `NLOHMANN_DEFINE_TYPE_INTRUSIVE(type, member...)`
- `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(type, member...)`
- `NLOHMANN_JSON_SERIALIZE_ENUM(type, ...)`
- `NLOHMANN_JSON_VERSION_MAJOR`, `NLOHMANN_JSON_VERSION_MINOR`, `NLOHMANN_JSON_VERSION_PATCH`
