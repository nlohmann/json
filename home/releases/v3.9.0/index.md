# v3.9.0

Released on 2020-07-27.

Feature release adding four long-requested features. All changes are backward-compatible.

- Optional [comment](https://json.nlohmann.me/features/comments/index.md) parsing in [`parse`](https://json.nlohmann.me/api/basic_json/parse/index.md) via the `ignore_comments` parameter.
- [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md) to preserve the [insertion order](https://json.nlohmann.me/features/object_order/index.md) of object keys.
- An option to switch off [implicit conversions](https://json.nlohmann.me/api/macros/json_use_implicit_conversions/index.md).
- The [`NLOHMANN_DEFINE_TYPE_*`](https://json.nlohmann.me/features/arbitrary_types/#simplify-your-life-with-macros) convenience macros, plus high-precision-number support for [UBJSON](https://json.nlohmann.me/features/binary_formats/ubjson/index.md) and CBOR tag handling.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.9.0).

## API changes

**Added (6 pages):**

- [`ordered_map`](https://json.nlohmann.me/api/ordered_map/index.md)
- `basic_json`: [`cbor_tag_handler_t`](https://json.nlohmann.me/api/basic_json/cbor_tag_handler_t/index.md)
- `macros`: [`JSON_ASSERT`](https://json.nlohmann.me/api/macros/json_assert/index.md), [`JSON_USE_IMPLICIT_CONVERSIONS`](https://json.nlohmann.me/api/macros/json_use_implicit_conversions/index.md), [`NLOHMANN_DEFINE_TYPE_INTRUSIVE, NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT, NLOHMANN_DEFINE_TYPE_INTRUSIVE_ONLY_SERIALIZE`](https://json.nlohmann.me/api/macros/nlohmann_define_type_intrusive/index.md), [`NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE, NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT, NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE`](https://json.nlohmann.me/api/macros/nlohmann_define_type_non_intrusive/index.md)

**Changed:**

- [`basic_json::accept`](https://json.nlohmann.me/api/basic_json/accept/index.md): Ignoring comments via `ignore_comments` added in version 3.9.0.
- [`basic_json::from_cbor`](https://json.nlohmann.me/api/basic_json/from_cbor/index.md): Added `tag_handler` parameter in version 3.9.0.
- [`basic_json::operator ValueType`](https://json.nlohmann.me/api/basic_json/operator_ValueType/index.md): Macros `JSON_EXPLICIT`/[`JSON_USE_IMPLICIT_CONVERSIONS`](https://json.nlohmann.me/api/macros/json_use_implicit_conversions/index.md) added in version 3.9.0.
- [`basic_json::parse`](https://json.nlohmann.me/api/basic_json/parse/index.md): Ignoring comments via `ignore_comments` added in version 3.9.0.
- [`basic_json::sax_parse`](https://json.nlohmann.me/api/basic_json/sax_parse/index.md): Ignoring comments via `ignore_comments` added in version 3.9.0.
