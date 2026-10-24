# v2.0.0

Released on 2016-06-24.

Feature release with a minor (potentially non-backward-compatible) API change from added `noexcept` and `constexpr` specifiers.

- Adds [JSON Pointer](https://json.nlohmann.me/features/json_pointer/index.md) support in [`at`](https://json.nlohmann.me/api/basic_json/at/index.md) and [`operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md), plus [`flatten`](https://json.nlohmann.me/api/basic_json/flatten/index.md) and [`unflatten`](https://json.nlohmann.me/api/basic_json/unflatten/index.md).
- Adds [JSON Patch](https://json.nlohmann.me/features/json_patch/index.md) via [`diff`](https://json.nlohmann.me/api/basic_json/diff/index.md) and [`patch`](https://json.nlohmann.me/api/basic_json/patch/index.md), unsigned 64-bit integer support, and locale-independent serialization.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v2.0.0).

## API changes

**Added (11 pages):**

- [`operator""_json_pointer`](https://json.nlohmann.me/api/operator_literal_json_pointer/index.md)
- `basic_json`: [`diff`](https://json.nlohmann.me/api/basic_json/diff/index.md), [`flatten`](https://json.nlohmann.me/api/basic_json/flatten/index.md), [`is_number_unsigned`](https://json.nlohmann.me/api/basic_json/is_number_unsigned/index.md), [`number_unsigned_t`](https://json.nlohmann.me/api/basic_json/number_unsigned_t/index.md), [`patch`](https://json.nlohmann.me/api/basic_json/patch/index.md), [`unflatten`](https://json.nlohmann.me/api/basic_json/unflatten/index.md)
- `json_pointer`: [(overview)](https://json.nlohmann.me/api/json_pointer/index.md), [`json_pointer`](https://json.nlohmann.me/api/json_pointer/json_pointer/index.md), [`operator string_t`](https://json.nlohmann.me/api/json_pointer/operator_string_t/index.md), [`to_string`](https://json.nlohmann.me/api/json_pointer/to_string/index.md)

**Changed:**

- [`basic_json::at`](https://json.nlohmann.me/api/basic_json/at/index.md): Overload 4 added.
- [`basic_json::is_number`](https://json.nlohmann.me/api/basic_json/is_number/index.md): Extended to also return `true` for unsigned integers in 2.0.0.
- [`basic_json::is_number_integer`](https://json.nlohmann.me/api/basic_json/is_number_integer/index.md): Extended to also return `true` for unsigned integers in 2.0.0.
- [`basic_json::operator+=`](https://json.nlohmann.me/api/basic_json/operator%2B%3D/index.md): Overload 3 added.
- [`basic_json::operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md): Overload 4 added.
- [`basic_json::operator value_t`](https://json.nlohmann.me/api/basic_json/operator_value_t/index.md): Added unsigned integer type in version 2.0.0.
- [`basic_json::push_back`](https://json.nlohmann.me/api/basic_json/push_back/index.md): Overload 3 added.
- [`basic_json::type`](https://json.nlohmann.me/api/basic_json/type/index.md): Added unsigned integer type in version 2.0.0.
- [`basic_json::value_t`](https://json.nlohmann.me/api/basic_json/value_t/index.md): Added unsigned integer type in version 2.0.0.
