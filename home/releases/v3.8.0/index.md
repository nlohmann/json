# v3.8.0

Released on 2020-06-14.

Feature release. All changes are backward-compatible.

- Introduces a [binary value](https://json.nlohmann.me/features/binary_values/index.md) type that is read from and written to [CBOR](https://json.nlohmann.me/features/binary_formats/cbor/index.md), [BSON](https://json.nlohmann.me/features/binary_formats/bson/index.md), and [MessagePack](https://json.nlohmann.me/features/binary_formats/messagepack/index.md), and can be shared between formats.
- Generalizes the input adapters to read from any `LegacyInputIterator` container (3–10 % faster parsing).
- Fixes [`contains`](https://json.nlohmann.me/api/basic_json/contains/index.md) for JSON pointers and makes the binary [`from_cbor`](https://json.nlohmann.me/api/basic_json/from_cbor/index.md)/[`from_msgpack`](https://json.nlohmann.me/api/basic_json/from_msgpack/index.md)/etc. functions respect `allow_exceptions`.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.8.0).

## API changes

**Added (9 pages):**

- `basic_json`: [`binary`](https://json.nlohmann.me/api/basic_json/binary/index.md), [`binary_t`](https://json.nlohmann.me/api/basic_json/binary_t/index.md), [`get_binary`](https://json.nlohmann.me/api/basic_json/get_binary/index.md), [`is_binary`](https://json.nlohmann.me/api/basic_json/is_binary/index.md)
- `byte_container_with_subtype`: [(overview)](https://json.nlohmann.me/api/byte_container_with_subtype/index.md), [`operator==`](https://json.nlohmann.me/api/byte_container_with_subtype/operator_eq/index.md), [`operator!=`](https://json.nlohmann.me/api/byte_container_with_subtype/operator_ne/index.md), [`subtype`](https://json.nlohmann.me/api/byte_container_with_subtype/subtype/index.md)
- `json_sax`: [`binary`](https://json.nlohmann.me/api/json_sax/binary/index.md)

**Changed:**

- [`basic_json::back`](https://json.nlohmann.me/api/basic_json/back/index.md): Binary values are supported since version 3.8.0.
- [`basic_json::clear`](https://json.nlohmann.me/api/basic_json/clear/index.md): Added support for binary types in version 3.8.0.
- [`basic_json::dump`](https://json.nlohmann.me/api/basic_json/dump/index.md): Serialization of binary values added in version 3.8.0.
- [`basic_json::empty`](https://json.nlohmann.me/api/basic_json/empty/index.md): Extended to return `false` for binary types in version 3.8.0.
- [`basic_json::erase`](https://json.nlohmann.me/api/basic_json/erase/index.md): Overload 1: Added support for binary types in version 3.8.0.
- [`basic_json::erase`](https://json.nlohmann.me/api/basic_json/erase/index.md): Overload 2: Added support for binary types in version 3.8.0.
- [`basic_json::front`](https://json.nlohmann.me/api/basic_json/front/index.md): Binary values are supported since version 3.8.0.
- [`basic_json::get_ptr`](https://json.nlohmann.me/api/basic_json/get_ptr/index.md): Extended to binary types in version 3.8.0.
- [`basic_json::get_ref`](https://json.nlohmann.me/api/basic_json/get_ref/index.md): Extended to binary types in version 3.8.0.
- [`basic_json::is_primitive`](https://json.nlohmann.me/api/basic_json/is_primitive/index.md): Extended to return `true` for binary types in version 3.8.0.
- [`basic_json::max_size`](https://json.nlohmann.me/api/basic_json/max_size/index.md): Extended to return `1` for binary types in version 3.8.0.
- [`basic_json::operator value_t`](https://json.nlohmann.me/api/basic_json/operator_value_t/index.md): Added binary type in version 3.8.0.
- [`basic_json::size`](https://json.nlohmann.me/api/basic_json/size/index.md): Extended to return `1` for binary types in version 3.8.0.
- [`basic_json::swap`](https://json.nlohmann.me/api/basic_json/swap/index.md): Overload 6 added.
- [`basic_json::swap`](https://json.nlohmann.me/api/basic_json/swap/index.md): Overload 7 added.
- [`basic_json::to_cbor`](https://json.nlohmann.me/api/basic_json/to_cbor/index.md): Compact representation of floating-point numbers added in version 3.8.0.
- [`basic_json::type`](https://json.nlohmann.me/api/basic_json/type/index.md): Added binary type in version 3.8.0.
- [`basic_json::type_name`](https://json.nlohmann.me/api/basic_json/type_name/index.md): Added support for binary type in version 3.8.0.
- [`basic_json::value_t`](https://json.nlohmann.me/api/basic_json/value_t/index.md): Added binary type in version 3.8.0.
- [`json_sax`](https://json.nlohmann.me/api/json_sax/index.md): Support for binary values (`binary_t`, `binary`) added in version 3.8.0.
