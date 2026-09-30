# JSON_NO_AUTOMATIC_UDLS

```cpp
#define JSON_NO_AUTOMATIC_UDLS
```

When defined, `<nlohmann/json.hpp>` does not include `<nlohmann/json_literals.hpp>`, so the user-defined string
literals [`operator""_json`](../operator_literal_json.md) and
[`operator""_json_pointer`](../operator_literal_json_pointer.md) are not declared. Include
`<nlohmann/json_literals.hpp>` in the files that use them.

The literals are ordinary inline functions whose bodies call the parser, so every translation unit that includes them
instantiates the parser — even if it never parses anything itself. Defining `JSON_NO_AUTOMATIC_UDLS` for a whole project
avoids this cost in translation units that do not parse (e.g., ones that only define types and conversions or pass
`json` values around) and reduces their compile time.

## Default definition

By default, `#!cpp JSON_NO_AUTOMATIC_UDLS` is not defined, and `<nlohmann/json.hpp>` includes
`<nlohmann/json_literals.hpp>`.

```cpp
#undef JSON_NO_AUTOMATIC_UDLS
```

## Notes

!!! info "Header `<nlohmann/json_literals.hpp>`"

    The header includes `<nlohmann/json.hpp>` itself and places the literals according to
    [`JSON_USE_GLOBAL_UDLS`](json_use_global_udls.md). It is part of the multi-header sources (`include/nlohmann`)
    and of the single-header sources (`single_include/nlohmann`), next to `json.hpp`.

!!! info "C++ modules"

    The `nlohmann.json` [module](../../features/modules.md) always exports the literals, regardless of this macro.

## Examples

??? example

    The code below includes the library without the literals and adds them in a single translation unit.

    ```cpp
    // compiled with -DJSON_NO_AUTOMATIC_UDLS for the whole project
    #include <nlohmann/json.hpp>

    // this file uses the literals, so it includes them explicitly
    #include <nlohmann/json_literals.hpp>

    int main()
    {
        auto j = R"({"foo": 42})"_json;
        return j.at("/foo"_json_pointer) == 42 ? 0 : 1;
    }
    ```

    Without the include of `<nlohmann/json_literals.hpp>`, the code would fail to compile.

## See also

- [`operator""_json`](../operator_literal_json.md)
- [`operator""_json_pointer`](../operator_literal_json_pointer.md)
- [`JSON_USE_GLOBAL_UDLS`](json_use_global_udls.md) - place user-defined string literals (UDLs) into the global namespace

## Version history

- Added in version 3.13.0.
