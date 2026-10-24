# v2.1.0

Released on 2017-01-28.

Feature release. All changes are backward-compatible.

- Adds conversions from and to [arbitrary user-defined types](https://json.nlohmann.me/features/arbitrary_types/index.md) via `to_json`/`from_json`, the [`meta`](https://json.nlohmann.me/api/basic_json/meta/index.md) function, and the option to switch off exceptions ([`JSON_NOEXCEPTION`](https://json.nlohmann.me/api/macros/json_noexception/index.md)).

[Full release notes](https://github.com/nlohmann/json/releases/tag/v2.1.0).

## API changes

**Added (7 pages):**

- `adl_serializer`: [(overview)](https://json.nlohmann.me/api/adl_serializer/index.md), [`from_json`](https://json.nlohmann.me/api/adl_serializer/from_json/index.md), [`to_json`](https://json.nlohmann.me/api/adl_serializer/to_json/index.md)
- `basic_json`: [`json_serializer`](https://json.nlohmann.me/api/basic_json/json_serializer/index.md), [`meta`](https://json.nlohmann.me/api/basic_json/meta/index.md)
- `json_pointer`: [`operator==`](https://json.nlohmann.me/api/json_pointer/operator_eq/index.md), [`operator!=`](https://json.nlohmann.me/api/json_pointer/operator_ne/index.md)

**Changed:**

- [`basic_json::basic_json`](https://json.nlohmann.me/api/basic_json/basic_json/index.md): Overload 3 added.
- [`basic_json::get`](https://json.nlohmann.me/api/basic_json/get/index.md): Overload 1 added.
- [`basic_json::get`](https://json.nlohmann.me/api/basic_json/get/index.md): Overload 2 added.
- [`basic_json::type_name`](https://json.nlohmann.me/api/basic_json/type_name/index.md): Part of the public API version since 2.1.0.
