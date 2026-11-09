# Reading values

## Getting values out without copying

[`get<T>()`](https://json.nlohmann.me/api/basic_json_view/get/index.md) converts most `T` directly from the flat index, without ever building a `basic_json` value for the conversion: `bool`, arithmetic types, `std::nullptr_t`, `std::string`/other `std::basic_string`s (copied once), `basic_json_view` itself, the standard containers and other types the library converts (`std::vector`, `std::map`, `std::list`, `std::array`, `std::pair`, `std::tuple`, `std::optional`, ...), and the types of the `NLOHMANN_DEFINE_TYPE_*` and `NLOHMANN_JSON_SERIALIZE_ENUM` macros. Types whose `from_json()` is written for `basic_json` only go through [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md)`.get<T>()` instead: the subtree is built into a real `basic_json` value first, exactly as [`parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md) would, and converted from there. See [A `from_json()` that reads views](https://json.nlohmann.me/features/json_view/generic_code/#a-from_json-that-reads-views) for how to write a `from_json()` that reads views, and [Duplicate keys](https://json.nlohmann.me/features/json_view/differences/#duplicate-keys) for the one case in which the two ways give different results.

Two conversions never copy at all:

- [`get_string()`](https://json.nlohmann.me/api/basic_json_view/get_string/index.md) (equivalently, `get<string_view_t>()`) returns a string as a `string_view_t` pointing into the document's [`source()`](https://json.nlohmann.me/api/basic_json_document/source/index.md) text — or, for a string that contains escape sequences, into the document's own buffer of decoded strings — instead of allocating a new `std::string`.
- [`number_token()`](https://json.nlohmann.me/api/basic_json_view/number_token/index.md) returns a number exactly as it was written in the source, e.g. `"1.50"`, `"1E2"`, or an integer with more digits than any number type holds, instead of rounding it into a `double`/`int64_t` the way `get<T>()` (and [`basic_json::parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md)) would.

Both results are only valid as long as the document and, if it [borrows its source text](https://json.nlohmann.me/features/json_view/lifetime/index.md), that text.

### `string_view` members

A struct whose member is a `std::string_view` (C++17) can be decoded from a view with the `NLOHMANN_DEFINE_TYPE_*` macros, and the member is not copied either: for a string without escape sequences it points into the document's source text, and for a string with escape sequences into the document's buffer of decoded strings. The member is valid as long as the document is alive and, for a document that [borrows its source text](https://json.nlohmann.me/features/json_view/lifetime/index.md) (as [`parse()`](https://json.nlohmann.me/api/basic_json_document/parse/index.md) does for an lvalue `std::string`, a `std::string_view`, or a C string), as long as that text is.

```
struct record
{
    std::string_view name;
    int count;
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(record, name, count)
};

const std::string text = R"({"name": "widget", "count": 3})";
const json_document doc = json_document::parse(text);  // borrows text
const record r = doc.root().get<record>();             // r.name points into text, valid while text and doc are
```

Decoding into a `string_view` from a `json` value dangles at once

The same struct also compiles with `json::parse(text).get<record>()`, but there `name` points into the temporary `json` value, which is destroyed at the end of the statement. Use a named [`json_document`](https://json.nlohmann.me/api/json_document/index.md), as above, to decode such a struct.

## Writing a view back

[`dump()`](https://json.nlohmann.me/api/basic_json_view/dump/index.md) serializes a view directly from the flat index, without ever building a `basic_json` value. It writes object members in document order and every occurrence of a repeated key, so it can differ from `materialize().dump()`; see [Serialization](https://json.nlohmann.me/features/json_view/differences/#serialization).

By default, numbers are written the way [`basic_json::dump()`](https://json.nlohmann.me/api/basic_json/dump/index.md) would. [`number_format::source`](https://json.nlohmann.me/api/basic_json_view/number_format/index.md) instead copies every number exactly as it was written in the source text — a price like `19.90`, a long order or account ID with more digits than any number type holds, or a high-precision coordinate — something `basic_json` cannot do at all, since parsing already reduces a number to its parsed `double`/`int64_t` value. Together with an [editable document](https://json.nlohmann.me/features/json_view/editing/index.md), this lets you patch a file without reformatting the rest of it.

[`operator<<`](https://json.nlohmann.me/api/basic_json_view/operator_ltlt/index.md) writes a view to a stream the way `basic_json`'s does, using the stream's `width`/`fill` for indentation.

## See also

- [Zero-copy JSON views](https://json.nlohmann.me/features/json_view/index.md) - overview
- [`get`](https://json.nlohmann.me/api/basic_json_view/get/index.md) - convert a view
- [`dump`](https://json.nlohmann.me/api/basic_json_view/dump/index.md) - serialize a view
- [Writing generic code](https://json.nlohmann.me/features/json_view/generic_code/index.md) - functions and `from_json()` overloads that accept views

## Version history

- Added in version 3.13.0 unreleased.
