# v3.11.2

Released on 2022-08-12.

Fixes bugs found in 3.11.1 and restructures the namespace. All changes are backward-compatible.

- Fixes the [`value`](https://json.nlohmann.me/api/basic_json/value/index.md) function (broken for strings, size types, and `nullptr` in 3.11.0) and makes `json_fwd.hpp` self-contained.
- Restores using [`json_pointer`](https://json.nlohmann.me/api/json_pointer/index.md) as a key in associative containers and comparing it with strings.
- Restructures the inline [namespace](https://json.nlohmann.me/features/namespace/index.md) and allows disabling the version component, and avoids heap allocations in the [BJData](https://json.nlohmann.me/features/binary_formats/bjdata/index.md) parser.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.11.2).

## API changes

**Added (2 pages):**

- `json_pointer`: [`operator<=>`](https://json.nlohmann.me/api/json_pointer/operator_spaceship/index.md)
- `macros`: [`NLOHMANN_JSON_NAMESPACE_NO_VERSION`](https://json.nlohmann.me/api/macros/nlohmann_json_namespace_no_version/index.md)

**Changed:**

- [`basic_json::value`](https://json.nlohmann.me/api/basic_json/value/index.md): Overload 2: Made `ValueType` the first template parameter in version 3.11.2.
- [`json_pointer::operator==`](https://json.nlohmann.me/api/json_pointer/operator_eq/index.md): Overload 1: Added C++20 member functions in version 3.11.2.
- [`json_pointer::operator==`](https://json.nlohmann.me/api/json_pointer/operator_eq/index.md): Overload 2: Added for backward compatibility and deprecated in version 3.11.2.
- [`json_pointer::operator!=`](https://json.nlohmann.me/api/json_pointer/operator_ne/index.md): Overload 2: Added for backward compatibility and deprecated in version 3.11.2.
- [`NLOHMANN_JSON_NAMESPACE`](https://json.nlohmann.me/api/macros/nlohmann_json_namespace/index.md): Changed inline namespace name in version 3.11.2.
- [`NLOHMANN_JSON_NAMESPACE_BEGIN, NLOHMANN_JSON_NAMESPACE_END`](https://json.nlohmann.me/api/macros/nlohmann_json_namespace_begin/index.md): Changed inline namespace name in version 3.11.2.
