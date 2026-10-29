# v3.4.0

Released on 2018-10-30.

Feature release. All changes are backward-compatible.

- Adds [BSON](https://json.nlohmann.me/features/binary_formats/bson/index.md) read/write support.
- Adds configurable Unicode error handlers to [`dump`](https://json.nlohmann.me/api/basic_json/dump/index.md) (throw, replace with U+FFFD, or ignore) and the [`NLOHMANN_JSON_SERIALIZE_ENUM`](https://json.nlohmann.me/api/macros/nlohmann_json_serialize_enum/index.md) macro for [enum conversion](https://json.nlohmann.me/features/enum_conversion/index.md).
- Improves parse-error messages with line/column positions and context.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.4.0).

## API changes

**Added (3 pages):**

- `basic_json`: [`error_handler_t`](https://json.nlohmann.me/api/basic_json/error_handler_t/index.md), [`from_bson`](https://json.nlohmann.me/api/basic_json/from_bson/index.md), [`to_bson`](https://json.nlohmann.me/api/basic_json/to_bson/index.md)

**Changed:**

- [`basic_json::dump`](https://json.nlohmann.me/api/basic_json/dump/index.md): Error handlers added in version 3.4.0.
- [`json_sax::key`](https://json.nlohmann.me/api/json_sax/key/index.md): BSON is only supported from version 3.4.0, and BON8 only from version 3.13.0 unreleased.
