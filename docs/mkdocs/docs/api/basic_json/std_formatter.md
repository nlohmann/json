# <small>std::</small>formatter<nlohmann::basic_json\>

```cpp
namespace std {
    template <>
    struct formatter<nlohmann::basic_json, char>;
}
```

Specialization to make JSON values formattable with [`std::format`](https://en.cppreference.com/w/cpp/utility/format/format)
(and the other members of C++20's `<format>` header, such as `std::format_to`).

Only an empty format spec (`#!cpp "{}"`) or the single flag `#!cpp "{:#}"` are accepted; any other spec
throws [`std::format_error`](https://en.cppreference.com/w/cpp/utility/format/format_error).

- `#!cpp "{}"` serializes the value the same way as [`dump()`](dump.md) (compact, no whitespace).
- `#!cpp "{:#}"` serializes the value the same way as `#!cpp dump(4)` (pretty-printed with an indent of 4).

This specialization is only available for `#!cpp char`-based JSON values and only if the standard library
provides `<format>`, controlled by the [`JSON_HAS_STD_FORMAT`](../macros/json_has_std_format.md) macro.

## Examples

??? example

    The example shows how to format JSON values with `std::format`.

    ```cpp
    --8<-- "examples/std_formatter.c++20.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/std_formatter.c++20.output"
    ```

## See also

- [dump](dump.md) - serialization
- [operator<<(std::ostream&)](../operator_ltlt.md) - serialize to stream
- [format_as](format_as.md) - customization point used by `fmt::format` (fmtlib)

## Version history

- Added in version 3.12.x.
