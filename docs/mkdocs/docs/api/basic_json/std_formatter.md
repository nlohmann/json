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
supported, repurposed for JSON pretty-printing and number formatting. Any other spec component (sign, the
`0` flag, `L`, a dynamic width or precision such as `#!cpp "{:{}}"`, or a trailing type character) throws
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
- A precision (e.g. `#!cpp "{:.3}"`) writes floating-point numbers with that many significant digits,
  exactly as `#!cpp std::format("{:.3}", x)` writes a floating-point number `x` (and as
  `#!c printf("%.3g", x)` does). For example, π becomes `#!json 3.14`, `#!json 1.9999` becomes `#!json 2.0`,
  and `#!json 12345.678` becomes `#!json 1.23e+04`. A number that would otherwise read back as an integer
  gets a `.0`. Integers are always written exactly, and NaN and infinity are still written as
  `#!json null`. It combines with the specs above, e.g. `#!cpp "{:#.3}"`.

This specialization is only available for `#!cpp char`-based JSON values and only if the standard library
provides `<format>`, controlled by the [`JSON_HAS_STD_FORMAT`](../macros/json_has_std_format.md) macro.

!!! warning "Precision and round-tripping"

    Without a precision, floating-point numbers are written with the shortest representation that parses back to
    the same value. With a precision, this guarantee is lost: `#!cpp json::parse(std::format("{:.3}", j))` can
    differ from `j`.

!!! note "Rounding"

    The digits are rounded from the exact binary value. `#!cpp 2.675` is stored as
    2.67499999999999982236431605997495353221893310546875, so `#!cpp std::format("{:.3}", json(2.675))` gives
    `#!json 2.67`, the same as `#!cpp std::format("{:.3}", 2.675)`, even though [`dump()`](dump.md) writes
    `#!json 2.675`.

!!! hint "Streams"

    There is no stream manipulator for the precision, but a formatted value can be written to a stream:
    `#!cpp os << std::format("{:.3}", j)`.

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

- Added in version 3.13.0.
