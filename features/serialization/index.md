# Serialization

Serialization is the process of turning a JSON value back into JSON text. It is the counterpart to [parsing](https://json.nlohmann.me/features/parsing/index.md). The central function is [`dump`](https://json.nlohmann.me/api/basic_json/dump/index.md), which returns the JSON text as a string.

```
json j = {{"pi", 3.141}, {"happy", true}};

std::string s = j.dump();   // {"happy":true,"pi":3.141}
```

To write a value directly to a stream (for example, a file or `std::cout`), the [`operator<<`](https://json.nlohmann.me/api/operator_ltlt/index.md) is provided:

```
std::cout << j << std::endl;
```

String, not raw value

`dump` always returns a **JSON text**. Serializing a JSON string therefore includes the surrounding quotes and escapes special characters. To obtain the *contained* string value without quotes, use [`get<std::string>()`](https://json.nlohmann.me/features/conversions/index.md) instead of `dump`. See the [converting values](https://json.nlohmann.me/features/conversions/index.md) page.

## Pretty-printing

By default, `dump` produces the most compact representation without any superfluous whitespace. Passing a non-negative `indent` argument pretty-prints the output with the given number of spaces per level:

Example

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON values
    json j_object = {{"one", 1}, {"two", 2}};
    json j_array = {1, 2, 4, 8, 16};
    json j_string = "Hellö 😀!";

    // call dump()
    std::cout << "objects:" << '\n'
              << j_object.dump() << "\n\n"
              << j_object.dump(-1) << "\n\n"
              << j_object.dump(0) << "\n\n"
              << j_object.dump(4) << "\n\n"
              << j_object.dump(1, '\t') << "\n\n";

    std::cout << "arrays:" << '\n'
              << j_array.dump() << "\n\n"
              << j_array.dump(-1) << "\n\n"
              << j_array.dump(0) << "\n\n"
              << j_array.dump(4) << "\n\n"
              << j_array.dump(1, '\t') << "\n\n";

    std::cout << "strings:" << '\n'
              << j_string.dump() << '\n'
              << j_string.dump(-1, ' ', true) << '\n';

    // create JSON value with invalid UTF-8 byte sequence
    json j_invalid = "ä\xA9ü";
    try
    {
        std::cout << j_invalid.dump() << std::endl;
    }
    catch (const json::type_error& e)
    {
        std::cout << e.what() << std::endl;
    }

    std::cout << "string with replaced invalid characters: "
              << j_invalid.dump(-1, ' ', false, json::error_handler_t::replace)
              << "\nstring with ignored invalid characters: "
              << j_invalid.dump(-1, ' ', false, json::error_handler_t::ignore)
              << '\n';
}
```

Output:

```
objects:
{"one":1,"two":2}

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
    "one": 1,
    "two": 2
}

arrays:
[1,2,4,8,16]

[1,2,4,8,16]

[
1,
2,
4,
8,
16
]

[
    1,
    2,
    4,
    8,
    16
]

[
    1,
    2,
    4,
    8,
    16
]

strings:
"Hellö 😀!"
"Hell\u00f6 \ud83d\ude00!"
[json.exception.type_error.316] invalid UTF-8 byte at index 2: 0xA9
string with replaced invalid characters: "ä�ü"
string with ignored invalid characters: "äü"
```

The indentation character can be changed with the second argument (e.g., a tab `'\t'`). An `indent` of `0` inserts newlines but no leading spaces, and the default of `-1` selects the compact single-line form.

## Non-ASCII characters

Strings are stored and serialized as UTF-8 (see [types](https://json.nlohmann.me/features/types/#strings)). By default, `dump` copies valid non-ASCII characters as-is. Setting the third argument `ensure_ascii` to `true` escapes all non-ASCII characters with `\uXXXX` sequences, so that the output contains only ASCII characters:

```
json j = "苹果";
j.dump();               // "苹果"
j.dump(-1, ' ', true);  // "苹果"
```

## Handling invalid UTF-8

If a string contains invalid UTF-8 sequences (for example, because it holds data in another encoding such as Latin-1), serialization fails by default. The fourth argument of `dump` selects an [`error_handler`](https://json.nlohmann.me/api/basic_json/error_handler_t/index.md):

- `strict` (default) — throw a [`type_error.316`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error316) exception.
- `replace` — replace invalid bytes with the Unicode replacement character U+FFFD (`�`).
- `ignore` — silently drop invalid bytes.

Example

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON value with invalid UTF-8 byte sequence
    json j_invalid = "ä\xA9ü";
    try
    {
        std::cout << j_invalid.dump() << std::endl;
    }
    catch (const json::type_error& e)
    {
        std::cout << e.what() << std::endl;
    }

    std::cout << "string with replaced invalid characters: "
              << j_invalid.dump(-1, ' ', false, json::error_handler_t::replace)
              << "\nstring with ignored invalid characters: "
              << j_invalid.dump(-1, ' ', false, json::error_handler_t::ignore)
              << '\n';
}
```

Output:

```
[json.exception.type_error.316] invalid UTF-8 byte at index 2: 0xA9
string with replaced invalid characters: "ä�ü"
string with ignored invalid characters: "äü"
```

Avoiding invalid UTF-8

The best fix is to ensure that all strings are UTF-8 encoded before storing them. See the [FAQ on non-ASCII characters](https://json.nlohmann.me/home/faq/#parse-errors-reading-non-ascii-characters) for how to convert wide or Latin-1 strings.

## Numbers, NaN, and binary values

- **Numbers** are serialized with enough precision to round-trip; see [number serialization](https://json.nlohmann.me/features/types/number_handling/#number-serialization).
- **NaN and infinity** cannot be represented in JSON and are serialized as `null`; see [NaN handling](https://json.nlohmann.me/features/types/number_handling/#nan-handling). The [binary formats](https://json.nlohmann.me/features/binary_formats/index.md) can preserve them.
- **Binary values** have no JSON representation and are serialized as a helper object for debugging only; see [binary values](https://json.nlohmann.me/features/binary_values/#serialization).

## Using `std::format`, `std::print`, and `fmt`

Since version 3.12.0, JSON values can be formatted directly with C++20's [`std::format`](https://en.cppreference.com/w/cpp/utility/format/format) whenever the standard library provides the `<format>` header (controlled by [`JSON_HAS_STD_FORMAT`](https://json.nlohmann.me/api/macros/json_has_std_format/index.md)). This is enabled by the [`std::formatter<basic_json>`](https://json.nlohmann.me/api/basic_json/std_formatter/index.md) specialization, which also makes JSON values work with `std::format_to` and with C++23's `std::print`/`std::println`:

```
std::print("{}", j);      // compact, like j.dump()
std::print("{:2}", j);    // pretty-printed with indent 2 (like j.dump(2))
std::println("{:#}", j);  // pretty-printed with the default indent
```

The format spec mirrors the `dump` parameters: `"{:#}"` pretty-prints, a width such as `"{:2}"` sets the indent, and a fill-and-align prefix such as `"{:.>#}"` sets the indent character.

For the [{fmt}](https://github.com/fmtlib/fmt) library, the library ships a [`format_as`](https://json.nlohmann.me/api/basic_json/format_as/index.md) helper. Note its behavior depends on the `fmt` version; see the [FAQ entry](https://json.nlohmann.me/home/faq/#using-json-values-with-stdformat-or-fmt) for the details and a recipe for a full `fmt::formatter` specialization.

## Serializing to other formats

Besides JSON text, a value can also be serialized to the more compact [binary formats](https://json.nlohmann.me/features/binary_formats/index.md) (BJData, BSON, CBOR, MessagePack, UBJSON).

## See also

- [`dump`](https://json.nlohmann.me/api/basic_json/dump/index.md) - serialize to a JSON-formatted string
- [`operator<<`](https://json.nlohmann.me/api/operator_ltlt/index.md) - serialize to a stream
- [`to_string`](https://json.nlohmann.me/api/basic_json/to_string/index.md) - user-defined-conversion helper
- [`std::formatter<basic_json>`](https://json.nlohmann.me/api/basic_json/std_formatter/index.md) - use JSON values with `std::format` and `std::print`
- [`format_as`](https://json.nlohmann.me/api/basic_json/format_as/index.md) - use JSON values with the {fmt} library
- [Parsing](https://json.nlohmann.me/features/parsing/index.md) - the reverse operation
