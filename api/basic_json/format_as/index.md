# format_as(basic_json)

```
template <typename BasicJsonType>
std::string format_as(const BasicJsonType& j);
```

This function implements the [`format_as`](https://fmt.dev/latest/api/#formatting-user-defined-types) customization point used by the [{fmt}](https://github.com/fmtlib/fmt) library (fmtlib). It has no dependency on any `fmt` header and no effect at all unless a caller's translation unit also includes `fmt` and calls `fmt::format`/`fmt::print` on a JSON value.

## Template parameters

`BasicJsonType` : a specialization of [`basic_json`](https://json.nlohmann.me/api/basic_json/index.md)

## Return value

string containing the serialization of the JSON value (same as [`dump()`](https://json.nlohmann.me/api/basic_json/dump/index.md))

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes to any JSON value.

## Exceptions

Throws [`type_error.316`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error316) if a string stored inside the JSON value is not UTF-8 encoded

## Complexity

Linear.

## Possible implementation

```
template <typename BasicJsonType>
std::string format_as(const BasicJsonType& j)
{
    return j.dump();
}
```

## Notes

Version-dependent effect on fmt

`fmt` only picks up a `format_as` overload that returns a `std::string` in fmt **10.0.0 through 11.0.2**. Starting with fmt **11.1.0**, `fmt` restricts automatic `format_as` pickup to overloads that return an arithmetic type, so this function has no effect there (it is simply unused, not a compile error).

If you use fmt >= 11.1.0, or want the same pretty-print spec support that [`std::formatter<basic_json>`](https://json.nlohmann.me/api/basic_json/std_formatter/index.md) has (`"{:#}"`, a width to set the indent such as `"{:2}"`/`"{:#2}"`, and fill-and-align to pick the indent character such as `"{:.>#}"`), define your own `fmt::formatter` specialization mirroring the same logic:

```
template <>
struct fmt::formatter<nlohmann::json>
{
    // -1 means compact output (dump()); any value >= 0 means pretty-printed
    // output with that many spaces (or indent_char) per level.
    int indent = -1;
    char indent_char = ' ';

    constexpr auto parse(format_parse_context& ctx) -> format_parse_context::iterator
    {
        auto it = ctx.begin();
        const auto end = ctx.end();
        constexpr auto is_align = [](char c)
        {
            return c == '<' || c == '>' || c == '^';
        };

        // [[fill] align] - repurposed here to pick a custom indent character
        if (it != end && it + 1 != end && is_align(it[1]))
        {
            indent_char = *it;
            it += 2;
        }
        else if (it != end && is_align(*it))
        {
            ++it;
        }

        // ['#'] - "alternate form", used here to request pretty-printing with a
        // default indent of 4 (overridden by an explicit width below, if given)
        if (it != end && *it == '#')
        {
            indent = 4;
            ++it;
        }

        // [width] - repurposed here to pick the indent size; a width without '#'
        // implies pretty-printing since an indent otherwise has no meaning
        if (it != end && *it >= '1' && *it <= '9')
        {
            indent = 0;
            while (it != end && *it >= '0' && *it <= '9')
            {
                indent = (indent * 10) + (*it - '0');
                ++it;
            }
        }

        if (it != end && *it != '}')
        {
            throw fmt::format_error("invalid format args for nlohmann::json");
        }

        return it;
    }

    auto format(const nlohmann::json& j, format_context& ctx) const
    {
        const auto dumped = j.dump(indent, indent_char);
        return fmt::format_to(ctx.out(), "{}", dumped);
    }
};
```

This recipe isn't shipped by the library itself, since doing so would make `fmt` a build dependency (see the FAQ entry on [using JSON values with `std::format` or `fmt`](https://json.nlohmann.me/home/faq/#using-json-values-with-stdformat-or-fmt) for more background) — but it *is* compiled and exercised against a real, current `fmt` release as part of the library's own test suite (`tests/fmt_formatter`, via CMake `FetchContent`), so it's kept in sync with `std::formatter<basic_json>` and verified to actually work, not just illustrative.

## Examples

Example

The following code shows how the library's `format_as()` function integrates with `fmt::format`, allowing argument-dependent lookup.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON value
    json j = {{"one", 1}, {"two", 2}};

    // format_as() is found via argument-dependent lookup, the same way
    // fmt::format/fmt::print would find it
    auto j_str = format_as(j);

    std::cout << j_str << std::endl;
}
```

Output:

```
{"one":1,"two":2}
```

## See also

- [dump](https://json.nlohmann.me/api/basic_json/dump/index.md)
- [std::formatter](https://json.nlohmann.me/api/basic_json/std_formatter/index.md) - the `std::format` (C++20) equivalent
- [Serialization](https://json.nlohmann.me/features/serialization/index.md) - the serialization article

## Version history

- Added in version 3.13.0.
