# v3.11.0

Released on 2022-08-01.

One of the largest releases ever. All changes are backward-compatible.

- Allows `std::string_view` as object keys in [`at`](https://json.nlohmann.me/api/basic_json/at/index.md), [`operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md), [`value`](https://json.nlohmann.me/api/basic_json/value/index.md), [`erase`](https://json.nlohmann.me/api/basic_json/erase/index.md), [`find`](https://json.nlohmann.me/api/basic_json/find/index.md), [`contains`](https://json.nlohmann.me/api/basic_json/contains/index.md), and [`count`](https://json.nlohmann.me/api/basic_json/count/index.md).
- Adds the [BJData](https://json.nlohmann.me/features/binary_formats/bjdata/index.md) binary format (the fifth supported format).
- Improves C++20 support, including [`operator<=>`](https://json.nlohmann.me/api/basic_json/operator_spaceship/index.md) and `<ranges>`-compatible iterators.
- Adds a versioned, ABI-tagged inline [namespace](https://json.nlohmann.me/features/namespace/index.md) ([`NLOHMANN_JSON_NAMESPACE`](https://json.nlohmann.me/api/macros/nlohmann_json_namespace/index.md)) and the option to move the UDLs out of the global namespace ([`JSON_USE_GLOBAL_UDLS`](https://json.nlohmann.me/api/macros/json_use_global_udls/index.md)).
- Adds [`patch_inplace`](https://json.nlohmann.me/api/basic_json/patch_inplace/index.md), default values for the [conversion macros](https://json.nlohmann.me/features/arbitrary_types/#simplify-your-life-with-macros), and an option to disable enum serialization ([`JSON_DISABLE_ENUM_SERIALIZATION`](https://json.nlohmann.me/api/macros/json_disable_enum_serialization/index.md)).

This release introduced a UDL regression that was fixed in [3.11.1](https://github.com/nlohmann/json/releases/tag/v3.11.1). [Full release notes](https://github.com/nlohmann/json/releases/tag/v3.11.0).

## API changes

**Added (14 pages):**

- `basic_json`: [`default_object_comparator_t`](https://json.nlohmann.me/api/basic_json/default_object_comparator_t/index.md), [`from_bjdata`](https://json.nlohmann.me/api/basic_json/from_bjdata/index.md), [`operator<=>`](https://json.nlohmann.me/api/basic_json/operator_spaceship/index.md), [`patch_inplace`](https://json.nlohmann.me/api/basic_json/patch_inplace/index.md), [`to_bjdata`](https://json.nlohmann.me/api/basic_json/to_bjdata/index.md)
- `json_pointer`: [`string_t`](https://json.nlohmann.me/api/json_pointer/string_t/index.md)
- `macros`: [`JSON_DISABLE_ENUM_SERIALIZATION`](https://json.nlohmann.me/api/macros/json_disable_enum_serialization/index.md), [`JSON_HAS_RANGES`](https://json.nlohmann.me/api/macros/json_has_ranges/index.md), [`JSON_HAS_THREE_WAY_COMPARISON`](https://json.nlohmann.me/api/macros/json_has_three_way_comparison/index.md), [`JSON_SKIP_LIBRARY_VERSION_CHECK`](https://json.nlohmann.me/api/macros/json_skip_library_version_check/index.md), [`JSON_USE_GLOBAL_UDLS`](https://json.nlohmann.me/api/macros/json_use_global_udls/index.md), [`JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON`](https://json.nlohmann.me/api/macros/json_use_legacy_discarded_value_comparison/index.md), [`NLOHMANN_JSON_NAMESPACE`](https://json.nlohmann.me/api/macros/nlohmann_json_namespace/index.md), [`NLOHMANN_JSON_NAMESPACE_BEGIN, NLOHMANN_JSON_NAMESPACE_END`](https://json.nlohmann.me/api/macros/nlohmann_json_namespace_begin/index.md)

**Changed:**

- [`operator""_json`](https://json.nlohmann.me/api/operator_literal_json/index.md): Moved to namespace `nlohmann::literals::json_literals` in 3.11.0.
- [`operator""_json_pointer`](https://json.nlohmann.me/api/operator_literal_json_pointer/index.md): Moved to namespace `nlohmann::literals::json_literals` in 3.11.0.
- [`operator<<(basic_json), nlohmann::operator<<(json_pointer)`](https://json.nlohmann.me/api/operator_ltlt/index.md): Overload 2 added.
- [`ordered_map`](https://json.nlohmann.me/api/ordered_map/index.md): Added **key_compare** member in version 3.11.0.
- [`basic_json::at`](https://json.nlohmann.me/api/basic_json/at/index.md): Overload 3 added.
- [`basic_json::contains`](https://json.nlohmann.me/api/basic_json/contains/index.md): Overload 1 added.
- [`basic_json::contains`](https://json.nlohmann.me/api/basic_json/contains/index.md): Overload 2: Extended template `KeyType` to support comparable types in version 3.11.0.
- [`basic_json::count`](https://json.nlohmann.me/api/basic_json/count/index.md): Overload 1 added.
- [`basic_json::count`](https://json.nlohmann.me/api/basic_json/count/index.md): Overload 2: Changed to support comparable key types in version 3.11.0.
- [`basic_json::erase`](https://json.nlohmann.me/api/basic_json/erase/index.md): Overload 4 added.
- [`basic_json::find`](https://json.nlohmann.me/api/basic_json/find/index.md): Overload 1 added.
- [`basic_json::find`](https://json.nlohmann.me/api/basic_json/find/index.md): Overload 2: Changed to support comparable types in version 3.11.0.
- [`basic_json::object_comparator_t`](https://json.nlohmann.me/api/basic_json/object_comparator_t/index.md): Changed to be conditionally defined as `typename object_t::key_compare` or `default_object_comparator_t` in version 3.11.0.
- [`basic_json::operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md): Overload 2: The `T* key` overloads forward to overload 3 since version 3.11.0.
- [`basic_json::operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md): Overload 3 added.
- [`basic_json::operator==`](https://json.nlohmann.me/api/basic_json/operator_eq/index.md): Overload 1: Added C++20 member functions in version 3.11.0.
- [`basic_json::operator==`](https://json.nlohmann.me/api/basic_json/operator_eq/index.md): Overload 2: Added C++20 member functions in version 3.11.0.
- [`basic_json::operator>=`](https://json.nlohmann.me/api/basic_json/operator_ge/index.md): Overload 1: Conditionally removed since C++20 in version 3.11.0.
- [`basic_json::operator>=`](https://json.nlohmann.me/api/basic_json/operator_ge/index.md): Overload 2: Conditionally removed since C++20 in version 3.11.0.
- [`basic_json::operator>`](https://json.nlohmann.me/api/basic_json/operator_gt/index.md): Overload 1: Conditionally removed since C++20 in version 3.11.0.
- [`basic_json::operator>`](https://json.nlohmann.me/api/basic_json/operator_gt/index.md): Overload 2: Conditionally removed since C++20 in version 3.11.0.
- [`basic_json::operator<=`](https://json.nlohmann.me/api/basic_json/operator_le/index.md): Overload 1: Conditionally removed since C++20 in version 3.11.0.
- [`basic_json::operator<=`](https://json.nlohmann.me/api/basic_json/operator_le/index.md): Overload 2: Conditionally removed since C++20 in version 3.11.0.
- [`basic_json::operator<`](https://json.nlohmann.me/api/basic_json/operator_lt/index.md): Overload 1: Conditionally removed since C++20 in version 3.11.0.
- [`basic_json::operator<`](https://json.nlohmann.me/api/basic_json/operator_lt/index.md): Overload 2: Conditionally removed since C++20 in version 3.11.0.
- [`basic_json::operator!=`](https://json.nlohmann.me/api/basic_json/operator_ne/index.md): Overload 1: Added a C++20 member function in version 3.11.0.
- [`basic_json::value`](https://json.nlohmann.me/api/basic_json/value/index.md): Overload 1: Changed parameter `default_value` type from `const ValueType&` to `ValueType&&` in version 3.11.0.
- [`basic_json::value`](https://json.nlohmann.me/api/basic_json/value/index.md): Overload 2 added.
- [`json_pointer::back`](https://json.nlohmann.me/api/json_pointer/back/index.md): Changed return type to `string_t` in version 3.11.0.
- [`json_pointer`](https://json.nlohmann.me/api/json_pointer/index.md): Changed template parameter from `basic_json` to string type in version 3.11.0.
- [`json_pointer::json_pointer`](https://json.nlohmann.me/api/json_pointer/json_pointer/index.md): Changed type of `s` to `string_t` in version 3.11.0.
- [`json_pointer::operator/`](https://json.nlohmann.me/api/json_pointer/operator_slash/index.md): Overload 2: Changed type of `token` to `string_t` in version 3.11.0.
- [`json_pointer::operator/=`](https://json.nlohmann.me/api/json_pointer/operator_slasheq/index.md): Overload 2: Changed type of `token` to `string_t` in version 3.11.0.
- [`json_pointer::operator string_t`](https://json.nlohmann.me/api/json_pointer/operator_string_t/index.md): Changed type to `string_t` and deprecated in version 3.11.0.
- [`json_pointer::push_back`](https://json.nlohmann.me/api/json_pointer/push_back/index.md): Changed type of `token` to `string_t` in version 3.11.0.
- [`json_pointer::to_string`](https://json.nlohmann.me/api/json_pointer/to_string/index.md): Changed return type to `string_t` in version 3.11.0.
- [`JSON_DIAGNOSTICS`](https://json.nlohmann.me/api/macros/json_diagnostics/index.md): As of version 3.11.0, the definition is allowed to vary between translation units.
- [`NLOHMANN_DEFINE_TYPE_INTRUSIVE, NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT, NLOHMANN_DEFINE_TYPE_INTRUSIVE_ONLY_SERIALIZE`](https://json.nlohmann.me/api/macros/nlohmann_define_type_intrusive/index.md): Overload 2 added.
- [`NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE, NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT, NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE`](https://json.nlohmann.me/api/macros/nlohmann_define_type_non_intrusive/index.md): Overload 2 added.
