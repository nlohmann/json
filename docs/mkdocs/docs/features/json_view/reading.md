# Reading values

## Getting values out without copying

[`get<T>()`](../../api/basic_json_view/get.md) converts most `T` directly from the flat index, without ever building a
`basic_json` value for the conversion: `#!cpp bool`, arithmetic types, `#!cpp std::nullptr_t`,
`#!cpp std::string`/other `#!cpp std::basic_string`s (copied once), `basic_json_view` itself, the standard containers
and other types the library converts (`#!cpp std::vector`, `#!cpp std::map`, `#!cpp std::list`, `#!cpp std::array`,
`#!cpp std::pair`, `#!cpp std::tuple`, `#!cpp std::optional`, ...), and the types of the `NLOHMANN_DEFINE_TYPE_*` and
`NLOHMANN_JSON_SERIALIZE_ENUM` macros. Types whose `from_json()` is written for `basic_json` only go through
[`materialize()`](../../api/basic_json_view/materialize.md)`.get<T>()` instead: the subtree is built into a real
`basic_json` value first, exactly as [`parse()`](../../api/basic_json/parse.md) would, and converted from there. See
[A `from_json()` that reads views](generic_code.md#a-from_json-that-reads-views) for how to write a `from_json()` that
reads views, and [Duplicate keys](differences.md#duplicate-keys) for the one case in which the two ways give different
results.

Two conversions never copy at all:

- [`get_string()`](../../api/basic_json_view/get_string.md) (equivalently, `#!cpp get<string_view_t>()`) returns a
  string as a `string_view_t` pointing into the document's [`source()`](../../api/basic_json_document/source.md) text
  — or, for a string that contains escape sequences, into the document's own buffer of decoded strings — instead of
  allocating a new `#!cpp std::string`.
- [`number_token()`](../../api/basic_json_view/number_token.md) returns a number exactly as it was written in the
  source, e.g. `#!cpp "1.50"`, `#!cpp "1E2"`, or an integer with more digits than any number type holds, instead of
  rounding it into a `#!cpp double`/`#!cpp int64_t` the way `#!cpp get<T>()` (and
  [`basic_json::parse()`](../../api/basic_json/parse.md)) would.

Both results are only valid as long as the document and, if it [borrows its source text](lifetime.md), that text.

### `string_view` members

A struct whose member is a `#!cpp std::string_view` (C++17) can be decoded from a view with the
`NLOHMANN_DEFINE_TYPE_*` macros, and the member is not copied either: for a string without escape sequences it points
into the document's source text, and for a string with escape sequences into the document's buffer of decoded
strings. The member is valid as long as the document is alive and, for a document that
[borrows its source text](lifetime.md) (as [`parse()`](../../api/basic_json_document/parse.md) does for an lvalue
`#!cpp std::string`, a `#!cpp std::string_view`, or a C string), as long as that text is.

```cpp
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

!!! warning "Decoding into a `string_view` from a `json` value dangles at once"

    The same struct also compiles with `#!cpp json::parse(text).get<record>()`, but there `name` points into the
    temporary `json` value, which is destroyed at the end of the statement. Use a named
    [`json_document`](../../api/json_document.md), as above, to decode such a struct.

## Writing a view back

[`dump()`](../../api/basic_json_view/dump.md) serializes a view directly from the flat index, without ever building a
`basic_json` value. It writes object members in document order and every occurrence of a repeated key, so it can
differ from `#!cpp materialize().dump()`; see [Serialization](differences.md#serialization).

By default, numbers are written the way [`basic_json::dump()`](../../api/basic_json/dump.md) would.
[`number_format::source`](../../api/basic_json_view/number_format.md) instead copies every number exactly as it was
written in the source text — a price like `#!cpp 19.90`, a long order or account ID with more digits than any number
type holds, or a high-precision coordinate — something `basic_json` cannot do at all, since parsing already reduces
a number to its parsed `#!cpp double`/`#!cpp int64_t` value. Together with an [editable document](editing.md), this
lets you patch a file without reformatting the rest of it.

[`operator<<`](../../api/basic_json_view/operator_ltlt.md) writes a view to a stream the way `basic_json`'s does, using
the stream's `width`/`fill` for indentation.

## See also

- [Zero-copy JSON views](index.md) - overview
- [`get`](../../api/basic_json_view/get.md) - convert a view
- [`dump`](../../api/basic_json_view/dump.md) - serialize a view
- [Writing generic code](generic_code.md) - functions and `from_json()` overloads that accept views

## Version history

- Added in version 3.13.0.
