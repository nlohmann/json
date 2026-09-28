# JSON_NO_UDLS

```cpp
#define JSON_NO_UDLS
```

When defined, the user-defined string literals [`operator""_json`](../operator_literal_json.md) and
[`operator""_json_pointer`](../operator_literal_json_pointer.md) are not defined, neither in the namespace
`nlohmann::literals::json_literals` nor in the global namespace (regardless of
[`JSON_USE_GLOBAL_UDLS`](json_use_global_udls.md)).

The literals are ordinary inline functions whose bodies call the parser, so every translation unit that includes the
library instantiates the parser — even if it never parses anything itself. Defining `JSON_NO_UDLS` avoids this and
reduces the compile time of such translation units (e.g., ones that only define types and conversions or pass `json`
values around). Everything else in the library is unaffected; use [`parse`](../basic_json/parse.md) and the
[`json_pointer`](../json_pointer/json_pointer.md) constructor instead of the literals.

## Default definition

By default, `#!cpp JSON_NO_UDLS` is not defined.

```cpp
#undef JSON_NO_UDLS
```

## Notes

!!! info "Per translation unit"

    The macro only removes declarations, so it can be defined for some translation units and not for others. Code that
    uses `_json` or `_json_pointer` fails to compile when `JSON_NO_UDLS` is defined.

## Examples

??? example

    The code below leaves out the user-defined string literals and uses `parse` and the `json_pointer` constructor
    instead.

    ```cpp
    #define JSON_NO_UDLS 1
    #include <nlohmann/json.hpp>

    int main()
    {
        // auto j = R"({"foo": 42})"_json; // This line would fail to compile
        auto j = nlohmann::json::parse(R"({"foo": 42})");
        auto p = nlohmann::json::json_pointer("/foo");
        return j.at(p) == 42 ? 0 : 1;
    }
    ```

## See also

- [`operator""_json`](../operator_literal_json.md)
- [`operator""_json_pointer`](../operator_literal_json_pointer.md)
- [`JSON_USE_GLOBAL_UDLS`](json_use_global_udls.md) - place user-defined string literals (UDLs) into the global namespace

## Version history

- Added in version 3.13.0.
