# std::formatter<nlohmann::basic_json>

```
namespace std {
    template <>
    struct formatter<nlohmann::basic_json, char>;
}
```

Specialization to make JSON values formattable with [`std::format`](https://en.cppreference.com/w/cpp/utility/format/format) (and the other members of C++20's `<format>` header, such as `std::format_to`).

A subset of the [standard format spec grammar](https://en.cppreference.com/w/cpp/utility/format/spec) is supported, repurposed for JSON pretty-printing; any other spec component (sign, the `0` flag, precision, `L`, a dynamic width such as `"{:{}}"`, or a trailing type character) throws [`std::format_error`](https://en.cppreference.com/w/cpp/utility/format/format_error):

- `"{}"` serializes the value the same way as [`dump()`](https://json.nlohmann.me/api/basic_json/dump/index.md) (compact, no whitespace).
- `"{:#}"` ("alternate form") serializes the value the same way as `dump(4)` (pretty-printed with an indent of 4).
- A width, with or without `"#"` (e.g. `"{:2}"` or `"{:#2}"`), serializes the value the same way as `dump(width)` — a width on its own implies pretty-printing, since an indent size has no meaning for compact output.
- `fill-and-align` (e.g. `"{:.>#}"` or `"{:.>3}"`) picks a custom indent character, the same way as `dump(indent, indent_char)`. The alignment direction itself (`'<'`, `'>'`, `'^'`) has no separate meaning for JSON values — only the fill character before it is used, and any of the three directions is accepted.

This specialization is only available for `char`-based JSON values and only if the standard library provides `<format>`, controlled by the [`JSON_HAS_STD_FORMAT`](https://json.nlohmann.me/api/macros/json_has_std_format/index.md) macro.

## Examples

Example

The example shows how to format JSON values with `std::format`.

```
#include <format>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    json j = {{"one", 1}, {"two", 2}};

    // compact formatting, like dump()
    std::cout << std::format("{}", j) << "\n\n";

    // pretty-printed formatting, like dump(4)
    std::cout << std::format("{:#}", j) << "\n\n";

    // a width sets the indent, like dump(2)
    std::cout << std::format("{:2}", j) << "\n\n";

    // fill-and-align sets the indent character, like dump(4, '.')
    std::cout << std::format("{:.>#}", j) << std::endl;
}
```

Output:

```
{"one":1,"two":2}

{
    "one": 1,
    "two": 2
}

{
  "one": 1,
  "two": 2
}

{
...."one": 1,
...."two": 2
}
```

## See also

- [dump](https://json.nlohmann.me/api/basic_json/dump/index.md) - serialization
- [operator\<<(std::ostream&)](https://json.nlohmann.me/api/operator_ltlt/index.md) - serialize to stream
- [format_as](https://json.nlohmann.me/api/basic_json/format_as/index.md) - customization point used by `fmt::format` (fmtlib)
- [Serialization](https://json.nlohmann.me/features/serialization/index.md) - the serialization article

## Version history

- Added in version 3.12.x.
