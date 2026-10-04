# JSON_NO_AUTOMATIC_UDLS

```
#define JSON_NO_AUTOMATIC_UDLS
```

When defined, `<nlohmann/json.hpp>` does not include `<nlohmann/json_literals.hpp>`, so the user-defined string literals [`operator""_json`](https://json.nlohmann.me/api/operator_literal_json/index.md) and [`operator""_json_pointer`](https://json.nlohmann.me/api/operator_literal_json_pointer/index.md) are not declared. Include `<nlohmann/json_literals.hpp>` in the files that use them.

The literals are ordinary inline functions whose bodies call the parser, so every translation unit that includes them instantiates the parser — even if it never parses anything itself. Defining `JSON_NO_AUTOMATIC_UDLS` for a whole project avoids this cost in translation units that do not parse (e.g., ones that only define types and conversions or pass `json` values around) and reduces their compile time.

## Default definition

By default, `JSON_NO_AUTOMATIC_UDLS` is not defined, and `<nlohmann/json.hpp>` includes `<nlohmann/json_literals.hpp>`.

```
#undef JSON_NO_AUTOMATIC_UDLS
```

## Notes

Header `<nlohmann/json_literals.hpp>`

The header includes `<nlohmann/json.hpp>` itself and places the literals according to [`JSON_USE_GLOBAL_UDLS`](https://json.nlohmann.me/api/macros/json_use_global_udls/index.md). It is part of the multi-header sources (`include/nlohmann`) and of the single-header sources (`single_include/nlohmann`), next to `json.hpp`.

C++ modules

The `nlohmann.json` [module](https://json.nlohmann.me/features/modules/index.md) always exports the literals, regardless of this macro.

## Examples

Example

The code below includes the library without the literals and adds them in a single translation unit.

```
// compiled with -DJSON_NO_AUTOMATIC_UDLS for the whole project

// this file uses the literals, so it includes them explicitly
// (the header includes <nlohmann/json.hpp> itself)
#include <nlohmann/json_literals.hpp>

int main()
{
    auto j = R"({"foo": 42})"_json;
    return j.at("/foo"_json_pointer) == 42 ? 0 : 1;
}
```

Without the include of `<nlohmann/json_literals.hpp>`, the code would fail to compile.

## See also

- [`operator""_json`](https://json.nlohmann.me/api/operator_literal_json/index.md)
- [`operator""_json_pointer`](https://json.nlohmann.me/api/operator_literal_json_pointer/index.md)
- [`JSON_USE_GLOBAL_UDLS`](https://json.nlohmann.me/api/macros/json_use_global_udls/index.md) - place user-defined string literals (UDLs) into the global namespace
- [Compile times](https://json.nlohmann.me/integration/compile_times/index.md) - options to reduce compile times

## Version history

- Added in version 3.13.0 unreleased.
