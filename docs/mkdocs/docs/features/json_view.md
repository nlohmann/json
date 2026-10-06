# Zero-copy JSON views

`#!cpp <nlohmann/json_view.hpp>` adds a read-only, non-owning way to look at a parsed JSON text, as an alternative to
building a [`basic_json`](../api/basic_json/index.md) tree with [`parse()`](../api/basic_json/parse.md).

## The problem

[`basic_json::parse()`](../api/basic_json/parse.md) builds a tree of `basic_json` values: one allocation for every
array and object, and every string copied into its own `std::string`. That is the right trade-off when the program
goes on to read and write the value freely, but it does more work than necessary when only a small part of a large
JSON text is actually needed, or when the same text is parsed over and over (many small messages, for instance) and
most of the resulting tree is thrown away almost immediately.

## The idea

[`basic_json_document::parse()`](../api/basic_json_document/parse.md) parses the same JSON grammar, with the same
options, but instead of a tree it builds a flat index of the values it found: one
[16-byte entry](../home/architecture.md#node-index-of-json-views) per value (and one per object key), in document
order. Strings and numbers are not copied out of the input; they stay in the source text, and are only decoded when
actually needed (for a string, only if it contains escape sequences, into one shared buffer owned by the document).

[`basic_json_view`](../api/basic_json_view/index.md) is a small, trivially copyable handle (two pointers) into that
index. It gives you the read-only, type-inspection part of the `basic_json` interface --
[`type()`](../api/basic_json_view/type.md) and the `is_*()` predicates,
[`size()`](../api/basic_json_view/size.md)/[`empty()`](../api/basic_json_view/empty.md) -- without ever allocating a
`basic_json` value. When you do need an actual `basic_json` value for a subtree,
[`materialize()`](../api/basic_json_view/materialize.md) builds exactly the one
[`parse()`](../api/basic_json/parse.md) would have produced for it.

## How to use it

Include `<nlohmann/json_view.hpp>` in addition to (or instead of) `<nlohmann/json.hpp>`. Parse into a
[`json_document`](../api/json_document.md), inspect its [`root()`](../api/basic_json_document/root.md), and
`materialize()` when you need a real value:

??? example "Example: parse a document, inspect its root, and materialize it"

    ```cpp
    --8<-- "examples/json_document.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/json_document.output"
    ```

[`ordered_json_document`](../api/ordered_json_document.md) is the equivalent for
[`ordered_json`](../api/ordered_json.md), just as [`ordered_json`](../api/ordered_json.md) is to
[`json`](../api/json.md).

## Ownership and lifetime

A document either **borrows** the text it was parsed from, or **owns** its own copy of it; call
[`owns_source()`](../api/basic_json_document/owns_source.md) to find out which happened.
[`parse()`](../api/basic_json_document/parse.md) decides this from the value category and type of its argument (an
lvalue `#!cpp std::string` is borrowed; an rvalue `#!cpp std::string` is moved in, owned without a copy; a stream is
read into an owned buffer; and so on -- see [`parse`'s Notes](../api/basic_json_document/parse.md#notes) for the full
table). [`parse_copy()`](../api/basic_json_document/parse_copy.md) always owns a copy, regardless of the input.

!!! warning "A borrowed document depends on your buffer"

    If a document borrows its text, that text **must outlive the document** (and every view taken from it). Reading
    or writing through a view after the underlying buffer is gone is undefined behavior, exactly as it would be for
    a dangling `#!cpp std::string_view`.

A view is valid only while all of the following hold:

- the document is alive,
- the document has not been re-parsed since the view was taken (with [`read()`](../api/basic_json_document/read.md)
  or [`parse()`](../api/basic_json_document/parse.md) into it), and has not had
  [`shrink_to_fit()`](../api/basic_json_document/shrink_to_fit.md) called on it since, and
- if the document borrows its source text, that text is still alive.

Moving the document itself is fine and does **not** invalidate its views: the index is a separate heap allocation
that keeps its address across the move. Take a fresh view from [`root()`](../api/basic_json_document/root.md)
whenever any of the other conditions above was not met.

??? example "Example: borrowed and owned documents, and when views become invalid"

    ```cpp
    --8<-- "examples/json_view_ownership.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/json_view_ownership.output"
    ```

## What is the same as `parse()`

- **Accept/reject.** [`accept()`](../api/basic_json_document/accept.md) and
  [`parse()`](../api/basic_json_document/parse.md) accept and reject exactly the same inputs as
  [`basic_json::accept()`](../api/basic_json/accept.md)/[`basic_json::parse()`](../api/basic_json/parse.md), with the
  same `ignore_comments` and `ignore_trailing_commas` options.
- **Errors.** A failing parse throws the same exception -- the same id, message, and position -- because on failure
  the library's own parser is run on the same bytes to produce the diagnostic.
  `#!cpp allow_exceptions == false` gives a [discarded](../api/basic_json_document/is_discarded.md) document instead
  of throwing, just as it gives a discarded value for `#!cpp basic_json::parse()`.
- **Number classification.** An integer literal that does not fit into the 64-bit integer type becomes a
  floating-point value, exactly as it does for `#!cpp basic_json::parse()`.
- **Macros.** [`JSON_STRICT_NUL_HANDLING`](../api/macros/json_strict_nul_handling.md) and
  [`JSON_NOEXCEPTION`](../api/macros/json_noexception.md)/[`JSON_THROW_USER`](../api/macros/json_throw_user.md)
  behave the same way they do for `<nlohmann/json.hpp>`.

## What is different

- **Only 64-bit integers.** `basic_json_document<BasicJsonType>` requires `BasicJsonType::number_integer_t` and
  `number_unsigned_t` to both be 64 bits wide; this is a compile-time `#!cpp static_assert`.
- **A 4 GiB input limit.** An input of 4 GiB or more throws
  [`out_of_range.416`](../home/exceptions.md#jsonexceptionout_of_range416), a limit
  `#!cpp basic_json::parse()` does not have.
- **A stream is always read to its end.** There is no partial/streaming read of an `#!cpp std::istream`.
- **No source positions on `materialize()`.** Even with
  [`JSON_DIAGNOSTIC_POSITIONS`](../api/macros/json_diagnostic_positions.md) enabled,
  [`materialize()`](../api/basic_json_view/materialize.md) does not set them: there is no lexer run during the
  replay to record them.
- **Element access, iteration, `get<T>()`, JSON Pointer, `dump()`, and comparison are not (yet) provided** by
  `basic_json_view`. For now, [`materialize()`](../api/basic_json_view/materialize.md) is the way to get a value you
  can do those things with.

## Choosing between `json`, `ordered_json`, the SAX interface, and `json_view`

| | [`json`](../api/json.md) / [`ordered_json`](../api/ordered_json.md) | [SAX interface](parsing/sax_interface.md) | [`json_document`](../api/json_document.md) / [`json_view`](../api/json_view.md) |
|---|---|---|---|
| **Ownership** | owns every value | owns nothing; you decide what to keep, in your handler | borrows or owns the *text*; the index is always owned by the document |
| **Mutability** | freely mutable | not applicable (a one-shot event stream) | read-only |
| **What you get** | a full tree you can read, write, and keep as long as you like | a sequence of callbacks; whatever your handler builds from them | a flat index plus, on demand, [`materialize()`](../api/basic_json_view/materialize.md)d `json`/`ordered_json` values for the parts you actually use |
| **Typical use** | general-purpose JSON handling: config, request/response bodies you build or modify, anything you hold onto | validating or projecting a text into your own data structure without ever holding the whole thing as JSON | large or high-volume input where you only need part of it, or need it repeatedly, and can keep the source text (or a copy) alive for as long as the document lives |

## Version history

- Added in version 3.13.0.
