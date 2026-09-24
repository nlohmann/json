# Serialization

Serialization is the process of turning a JSON value back into JSON text. It is the counterpart to
[parsing](parsing/index.md). The central function is [`dump`](../api/basic_json/dump.md), which returns the JSON text as
a string.

```cpp
json j = {{"pi", 3.141}, {"happy", true}};

std::string s = j.dump();   // {"happy":true,"pi":3.141}
```

To write a value directly to a stream (for example, a file or `#!cpp std::cout`), the
[`operator<<`](../api/operator_ltlt.md) is provided:

```cpp
std::cout << j << std::endl;
```

!!! note "String, not raw value"

    `dump` always returns a **JSON text**. Serializing a JSON string therefore includes the surrounding quotes and
    escapes special characters. To obtain the *contained* string value without quotes, use
    [`get<std::string>()`](conversions.md) instead of `dump`. See the [converting values](conversions.md) page.

## Pretty-printing

By default, `dump` produces the most compact representation without any superfluous whitespace. Passing a non-negative
`indent` argument pretty-prints the output with the given number of spaces per level:

??? example

    ```cpp
    --8<-- "examples/dump.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/dump.output"
    ```

The indentation character can be changed with the second argument (e.g., a tab `#!cpp '\t'`). An `indent` of `0` inserts
newlines but no leading spaces, and the default of `#!cpp -1` selects the compact single-line form.

## Non-ASCII characters

Strings are stored and serialized as UTF-8 (see [types](types/index.md#strings)). By default, `dump` copies valid
non-ASCII characters as-is. Setting the third argument `ensure_ascii` to `#!cpp true` escapes all non-ASCII characters
with `\uXXXX` sequences, so that the output contains only ASCII characters:

```cpp
json j = "苹果";
j.dump();               // "苹果"
j.dump(-1, ' ', true);  // "苹果"
```

## Handling invalid UTF-8

If a string contains invalid UTF-8 sequences (for example, because it holds data in another encoding such as Latin-1),
serialization fails by default. The fourth argument of `dump` selects an
[`error_handler`](../api/basic_json/error_handler_t.md):

- `strict` (default) — throw a [`type_error.316`](../home/exceptions.md#jsonexceptiontype_error316) exception.
- `replace` — replace invalid bytes with the Unicode replacement character U+FFFD (`�`).
- `ignore` — silently drop invalid bytes.

??? example

    ```cpp
    --8<-- "examples/error_handler_t.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/error_handler_t.output"
    ```

!!! tip "Avoiding invalid UTF-8"

    The best fix is to ensure that all strings are UTF-8 encoded before storing them. See the
    [FAQ on non-ASCII characters](../home/faq.md#parse-errors-reading-non-ascii-characters) for how to convert wide or
    Latin-1 strings.

## Numbers, NaN, and binary values

- **Numbers** are serialized with enough precision to round-trip; see [number serialization](types/number_handling.md#number-serialization).
- **NaN and infinity** cannot be represented in JSON and are serialized as `#!json null`; see
  [NaN handling](types/number_handling.md#nan-handling). The [binary formats](binary_formats/index.md) can preserve
  them.
- **Binary values** have no JSON representation and are serialized as a helper object for debugging only; see
  [binary values](binary_values.md#serialization).

## Using `std::format`, `std::print`, and `fmt`

Since version 3.12.0, JSON values can be formatted directly with C++20's
[`std::format`](https://en.cppreference.com/w/cpp/utility/format/format) whenever the standard library provides the
`<format>` header (controlled by [`JSON_HAS_STD_FORMAT`](../api/macros/json_has_std_format.md)). This is enabled by the
[`std::formatter<basic_json>`](../api/basic_json/std_formatter.md) specialization, which also makes JSON values work with
`std::format_to` and with C++23's `std::print`/`std::println`:

```cpp
std::print("{}", j);      // compact, like j.dump()
std::print("{:2}", j);    // pretty-printed with indent 2 (like j.dump(2))
std::println("{:#}", j);  // pretty-printed with the default indent
```

The format spec mirrors the `dump` parameters: `#!cpp "{:#}"` pretty-prints, a width such as `#!cpp "{:2}"` sets the
indent, and a fill-and-align prefix such as `#!cpp "{:.>#}"` sets the indent character.

For the [{fmt}](https://github.com/fmtlib/fmt) library, the library ships a
[`format_as`](../api/basic_json/format_as.md) helper. Note its behavior depends on the `fmt` version; see the
[FAQ entry](../home/faq.md#using-json-values-with-stdformat-or-fmt) for the details and a recipe for a full
`fmt::formatter` specialization.

## Serializing to other formats

Besides JSON text, a value can also be serialized to the more compact [binary formats](binary_formats/index.md)
(BJData, BSON, CBOR, MessagePack, UBJSON).

## See also

- [`dump`](../api/basic_json/dump.md) - serialize to a JSON-formatted string
- [`operator<<`](../api/operator_ltlt.md) - serialize to a stream
- [`to_string`](../api/basic_json/to_string.md) - user-defined-conversion helper
- [`std::formatter<basic_json>`](../api/basic_json/std_formatter.md) - use JSON values with `std::format` and `std::print`
- [`format_as`](../api/basic_json/format_as.md) - use JSON values with the {fmt} library
- [Parsing](parsing/index.md) - the reverse operation
