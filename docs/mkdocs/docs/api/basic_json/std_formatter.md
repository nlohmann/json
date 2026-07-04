# <small>std::</small>formatter<nlohmann::basic_json\>

```cpp
namespace std {
    template <>
    struct formatter<nlohmann::basic_json, char>;
}
```

Specialization to make JSON values formattable with [`std::format`](https://en.cppreference.com/w/cpp/utility/format/format)
(and the other members of C++20's `<format>` header, such as `std::format_to`).

A subset of the [standard format spec grammar](https://en.cppreference.com/w/cpp/utility/format/spec) is
supported, repurposed for JSON pretty-printing; any other spec component (sign, the `0` flag, precision,
`L`, a dynamic width such as `#!cpp "{:{}}"`, or a trailing type character) throws
[`std::format_error`](https://en.cppreference.com/w/cpp/utility/format/format_error):

- `#!cpp "{}"` serializes the value the same way as [`dump()`](dump.md) (compact, no whitespace).
- `#!cpp "{:#}"` ("alternate form") serializes the value the same way as `#!cpp dump(4)` (pretty-printed
  with an indent of 4).
- A width, with or without `#!cpp "#"` (e.g. `#!cpp "{:2}"` or `#!cpp "{:#2}"`), serializes the value the
  same way as `#!cpp dump(width)` — a width on its own implies pretty-printing, since an indent size has
  no meaning for compact output.
- `fill-and-align` (e.g. `#!cpp "{:.>#}"` or `#!cpp "{:.>3}"`) picks a custom indent character, the same
  way as `#!cpp dump(indent, indent_char)`. The alignment direction itself (`#!cpp '<'`, `#!cpp '>'`,
  `#!cpp '^'`) has no separate meaning for JSON values — only the fill character before it is used, and
  any of the three directions is accepted.

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
- [Serialization](../../features/serialization.md) - the serialization article

## Version history

- Added in version 3.12.x.
