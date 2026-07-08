# Macros

Some aspects of the library can be configured by defining preprocessor macros **before** including the `json.hpp` header. See also the [macro overview page](https://json.nlohmann.me/features/macros/index.md).

## Runtime assertions

- [**JSON_ASSERT(x)**](https://json.nlohmann.me/api/macros/json_assert/index.md) - control behavior of runtime assertions

## Exceptions

- [**JSON_CATCH_USER(exception)**\
  **JSON_THROW_USER(exception)**\
  **JSON_TRY_USER**](https://json.nlohmann.me/api/macros/json_throw_user/index.md) - control exceptions
- [**JSON_DIAGNOSTICS**](https://json.nlohmann.me/api/macros/json_diagnostics/index.md) - control extended diagnostics
- [**JSON_DIAGNOSTIC_POSITIONS**](https://json.nlohmann.me/api/macros/json_diagnostic_positions/index.md) - access positions of elements
- [**JSON_NOEXCEPTION**](https://json.nlohmann.me/api/macros/json_noexception/index.md) - switch off exceptions

## Language support

- [**JSON_HAS_CPP_11**\
  **JSON_HAS_CPP_14**\
  **JSON_HAS_CPP_17**\
  **JSON_HAS_CPP_20**](https://json.nlohmann.me/api/macros/json_has_cpp_11/index.md) - set supported C++ standard
- [**JSON_HAS_FILESYSTEM**\
  **JSON_HAS_EXPERIMENTAL_FILESYSTEM**](https://json.nlohmann.me/api/macros/json_has_filesystem/index.md) - control `std::filesystem` support
- [**JSON_HAS_RANGES**](https://json.nlohmann.me/api/macros/json_has_ranges/index.md) - control `std::ranges` support
- [**JSON_HAS_STD_FORMAT**](https://json.nlohmann.me/api/macros/json_has_std_format/index.md) - control `std::format`/`std::formatter` support
- [**JSON_HAS_THREE_WAY_COMPARISON**](https://json.nlohmann.me/api/macros/json_has_three_way_comparison/index.md) - control 3-way comparison support
- [**JSON_NO_IO**](https://json.nlohmann.me/api/macros/json_no_io/index.md) - switch off functions relying on certain C++ I/O headers
- [**JSON_SKIP_UNSUPPORTED_COMPILER_CHECK**](https://json.nlohmann.me/api/macros/json_skip_unsupported_compiler_check/index.md) - do not warn about unsupported compilers
- [**JSON_USE_GLOBAL_UDLS**](https://json.nlohmann.me/api/macros/json_use_global_udls/index.md) - place user-defined string literals (UDLs) into the global namespace

## Library version

- [**JSON_SKIP_LIBRARY_VERSION_CHECK**](https://json.nlohmann.me/api/macros/json_skip_library_version_check/index.md) - skip library version check
- [**NLOHMANN_JSON_VERSION_MAJOR**\
  **NLOHMANN_JSON_VERSION_MINOR**\
  **NLOHMANN_JSON_VERSION_PATCH**](https://json.nlohmann.me/api/macros/nlohmann_json_version_major/index.md)
  - library version information

## Library namespace

- [**NLOHMANN_JSON_NAMESPACE**](https://json.nlohmann.me/api/macros/nlohmann_json_namespace/index.md) - full name of the `nlohmann` namespace
- [**NLOHMANN_JSON_NAMESPACE_BEGIN**\
  **NLOHMANN_JSON_NAMESPACE_END**](https://json.nlohmann.me/api/macros/nlohmann_json_namespace_begin/index.md) - open and close the library namespace
- [**NLOHMANN_JSON_NAMESPACE_NO_VERSION**](https://json.nlohmann.me/api/macros/nlohmann_json_namespace_no_version/index.md) - disable the version component of the inline namespace

## Type conversions

- [**JSON_BRACE_INIT_COPY_SEMANTICS**](https://json.nlohmann.me/api/macros/json_brace_init_copy_semantics/index.md) - opt in to copy/move semantics for single-element brace initialization
- [**JSON_DISABLE_ENUM_SERIALIZATION**](https://json.nlohmann.me/api/macros/json_disable_enum_serialization/index.md) - switch off default serialization/deserialization functions for enums
- [**JSON_USE_IMPLICIT_CONVERSIONS**](https://json.nlohmann.me/api/macros/json_use_implicit_conversions/index.md) - control implicit conversions

## Comparison behavior

- [**JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON**](https://json.nlohmann.me/api/macros/json_use_legacy_discarded_value_comparison/index.md) - control comparison of discarded values

## Serialization/deserialization macros

### Enums

- [**NLOHMANN_JSON_SERIALIZE_ENUM**](https://json.nlohmann.me/api/macros/nlohmann_json_serialize_enum/index.md) - serialize/deserialize an enum
- [**NLOHMANN_JSON_SERIALIZE_ENUM_STRICT**](https://json.nlohmann.me/api/macros/nlohmann_json_serialize_enum_strict/index.md) - serialize/deserialize an enum with exceptions

### Classes and structs

- [**NLOHMANN_DEFINE_TYPE_INTRUSIVE**](https://json.nlohmann.me/api/macros/nlohmann_define_type_intrusive/index.md) - serialize/deserialize a non-derived class with private members
- [**NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT**](https://json.nlohmann.me/api/macros/nlohmann_define_type_intrusive/index.md) - serialize/deserialize a non-derived class with private members; uses default values
- [**NLOHMANN_DEFINE_TYPE_INTRUSIVE_ONLY_SERIALIZE**](https://json.nlohmann.me/api/macros/nlohmann_define_type_intrusive/index.md) - serialize a non-derived class with private members
- [**NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE**](https://json.nlohmann.me/api/macros/nlohmann_define_type_non_intrusive/index.md) - serialize/deserialize a non-derived class
- [**NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT**](https://json.nlohmann.me/api/macros/nlohmann_define_type_non_intrusive/index.md) - serialize/deserialize a non-derived class; uses default values
- [**NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE**](https://json.nlohmann.me/api/macros/nlohmann_define_type_non_intrusive/index.md) - serialize a non-derived class
- [**NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE**](https://json.nlohmann.me/api/macros/nlohmann_define_derived_type/index.md) - serialize/deserialize a derived class with private members
- [**NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_DEFAULT**](https://json.nlohmann.me/api/macros/nlohmann_define_derived_type/index.md) - serialize/deserialize a derived class with private members; uses default values
- [**NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_ONLY_SERIALIZE**](https://json.nlohmann.me/api/macros/nlohmann_define_derived_type/index.md) - serialize a derived class with private members
- [**NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE**](https://json.nlohmann.me/api/macros/nlohmann_define_derived_type/index.md) - serialize/deserialize a derived class
- [**NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_DEFAULT**](https://json.nlohmann.me/api/macros/nlohmann_define_derived_type/index.md) - serialize/deserialize a derived class; uses default values
- [**NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE**](https://json.nlohmann.me/api/macros/nlohmann_define_derived_type/index.md) - serialize a derived class
- [**NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_NAMES**](https://json.nlohmann.me/api/macros/nlohmann_define_type_with_names/index.md) - serialize/deserialize a non-derived class with private members; uses custom names
- [**NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT_WITH_NAMES**](https://json.nlohmann.me/api/macros/nlohmann_define_type_with_names/index.md) - serialize/deserialize a non-derived class with private members; uses default values; uses custom names
- [**NLOHMANN_DEFINE_TYPE_INTRUSIVE_ONLY_SERIALIZE_WITH_NAMES**](https://json.nlohmann.me/api/macros/nlohmann_define_type_with_names/index.md) - serialize a non-derived class with private members; uses custom names
- [**NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_NAMES**](https://json.nlohmann.me/api/macros/nlohmann_define_type_with_names/index.md) - serialize/deserialize a non-derived class; uses custom names
- [**NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT_WITH_NAMES**](https://json.nlohmann.me/api/macros/nlohmann_define_type_with_names/index.md) - serialize/deserialize a non-derived class; uses default values; uses custom names
- [**NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE_WITH_NAMES**](https://json.nlohmann.me/api/macros/nlohmann_define_type_with_names/index.md) - serialize a non-derived class; uses custom names
- [**NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_NAMES**](https://json.nlohmann.me/api/macros/nlohmann_define_type_with_names/index.md) - serialize/deserialize a derived class with private members; uses custom names
- [**NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_DEFAULT_WITH_NAMES**](https://json.nlohmann.me/api/macros/nlohmann_define_type_with_names/index.md) - serialize/deserialize a derived class with private members; uses default values; uses custom names
- [**NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_ONLY_SERIALIZE_WITH_NAMES**](https://json.nlohmann.me/api/macros/nlohmann_define_type_with_names/index.md) - serialize a derived class with private members; uses custom names
- [**NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_NAMES**](https://json.nlohmann.me/api/macros/nlohmann_define_type_with_names/index.md) - serialize/deserialize a derived class; uses custom names
- [**NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_DEFAULT_WITH_NAMES**](https://json.nlohmann.me/api/macros/nlohmann_define_type_with_names/index.md) - serialize/deserialize a derived class; uses default values; uses custom names
- [**NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE_WITH_NAMES**](https://json.nlohmann.me/api/macros/nlohmann_define_type_with_names/index.md) - serialize a derived class; uses custom names
