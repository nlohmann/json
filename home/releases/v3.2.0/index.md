# v3.2.0

Released on 2018-08-20.

Feature release. All changes are backward-compatible.

- Adds a [SAX interface](https://json.nlohmann.me/features/parsing/sax_interface/index.md) and a non-recursive parser.
- Adds parsing from wide-string types (`std::wstring`, `std::u16string`, `std::u32string`), conversion to `std::string_view` (C++17), and round-tripping of `std::map`/`std::unordered_map` with non-string keys.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.2.0).

## API changes

**Added (16 pages):**

- `basic_json`: [`input_format_t`](https://json.nlohmann.me/api/basic_json/input_format_t/index.md), [`sax_parse`](https://json.nlohmann.me/api/basic_json/sax_parse/index.md)
- `json_sax`: [(overview)](https://json.nlohmann.me/api/json_sax/index.md), [`boolean`](https://json.nlohmann.me/api/json_sax/boolean/index.md), [`end_array`](https://json.nlohmann.me/api/json_sax/end_array/index.md), [`end_object`](https://json.nlohmann.me/api/json_sax/end_object/index.md), [`key`](https://json.nlohmann.me/api/json_sax/key/index.md), [`null`](https://json.nlohmann.me/api/json_sax/null/index.md), [`number_float`](https://json.nlohmann.me/api/json_sax/number_float/index.md), [`number_integer`](https://json.nlohmann.me/api/json_sax/number_integer/index.md), [`number_unsigned`](https://json.nlohmann.me/api/json_sax/number_unsigned/index.md), [`parse_error`](https://json.nlohmann.me/api/json_sax/parse_error/index.md), [`start_array`](https://json.nlohmann.me/api/json_sax/start_array/index.md), [`start_object`](https://json.nlohmann.me/api/json_sax/start_object/index.md), [`string`](https://json.nlohmann.me/api/json_sax/string/index.md)
- `macros`: [`JSON_SKIP_UNSUPPORTED_COMPILER_CHECK`](https://json.nlohmann.me/api/macros/json_skip_unsupported_compiler_check/index.md)

**Changed:**

- [`basic_json::from_cbor`](https://json.nlohmann.me/api/basic_json/from_cbor/index.md): Added `allow_exceptions` parameter in version 3.2.0.
- [`basic_json::from_msgpack`](https://json.nlohmann.me/api/basic_json/from_msgpack/index.md): Added `allow_exceptions` parameter in version 3.2.0.
- [`basic_json::from_ubjson`](https://json.nlohmann.me/api/basic_json/from_ubjson/index.md): Added `allow_exceptions` parameter in version 3.2.0.
