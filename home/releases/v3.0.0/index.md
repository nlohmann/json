# v3.0.0

Released on 2017-12-17.

First 3.x release — a major release with breaking changes (see the [migration guide](https://json.nlohmann.me/integration/migration_guide/index.md)).

- Introduces user-defined [exceptions](https://json.nlohmann.me/home/exceptions/index.md) (`json::exception` and subtypes, each with an identifier).
- Adds a non-throwing [`accept`](https://json.nlohmann.me/api/basic_json/accept/index.md) function and an `allow_exceptions` flag for [`parse`](https://json.nlohmann.me/api/basic_json/parse/index.md), and an [`update`](https://json.nlohmann.me/api/basic_json/update/index.md) function to merge objects.
- Adds streaming for CBOR and MessagePack and allows storing NaN/infinity.
- Non-UTF-8 strings now throw on serialization, and the iterator category changed to bidirectional.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.0.0).

## API changes

**Added (9 pages):**

- `basic_json`: [`accept`](https://json.nlohmann.me/api/basic_json/accept/index.md), [`exception`](https://json.nlohmann.me/api/basic_json/exception/index.md), [`invalid_iterator`](https://json.nlohmann.me/api/basic_json/invalid_iterator/index.md), [`object_comparator_t`](https://json.nlohmann.me/api/basic_json/object_comparator_t/index.md), [`other_error`](https://json.nlohmann.me/api/basic_json/other_error/index.md), [`out_of_range`](https://json.nlohmann.me/api/basic_json/out_of_range/index.md), [`parse_error`](https://json.nlohmann.me/api/basic_json/parse_error/index.md), [`type_error`](https://json.nlohmann.me/api/basic_json/type_error/index.md), [`update`](https://json.nlohmann.me/api/basic_json/update/index.md)

**Changed:**

- [`operator<<(basic_json), nlohmann::operator<<(json_pointer)`](https://json.nlohmann.me/api/operator_ltlt/index.md): Overload 1: Added support for indentation character and deprecated `std::ostream& operator>>(const basic_json& j, std::ostream& o)` in version 3.0.0.
- [`basic_json::dump`](https://json.nlohmann.me/api/basic_json/dump/index.md): Indentation character `indent_char`, option `ensure_ascii` and exceptions added in version 3.0.0.
- [`basic_json::from_cbor`](https://json.nlohmann.me/api/basic_json/from_cbor/index.md): Changed to consume input adapters, removed `start_index` parameter, and added `strict` parameter in version 3.0.0.
- [`basic_json::from_msgpack`](https://json.nlohmann.me/api/basic_json/from_msgpack/index.md): Changed to consume input adapters, removed `start_index` parameter, and added `strict` parameter in version 3.0.0.
- [`basic_json::insert`](https://json.nlohmann.me/api/basic_json/insert/index.md): Overload 5 added.
- [`basic_json::type_name`](https://json.nlohmann.me/api/basic_json/type_name/index.md): Changed return value to `const char*` and added `noexcept` in version 3.0.0.
