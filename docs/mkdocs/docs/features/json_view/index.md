# Zero-copy JSON views

`#!cpp <nlohmann/json_view.hpp>` adds a read-only, non-owning way to look at a parsed JSON text, as an alternative to
building a [`basic_json`](../../api/basic_json/index.md) tree with [`parse()`](../../api/basic_json/parse.md).

## The problem

[`basic_json::parse()`](../../api/basic_json/parse.md) builds a tree of `basic_json` values: one allocation for every
array and object, and every string copied into its own `std::string`. That is the right trade-off when the program
goes on to read and write the value freely, but it does more work than necessary when only a small part of a large
JSON text is actually needed, or when the same text is parsed over and over (many small messages, for instance) and
most of the resulting tree is thrown away almost immediately.

## The idea

[`basic_json_document::parse()`](../../api/basic_json_document/parse.md) parses the same JSON grammar, with the same
options, but instead of a tree it builds a flat index of the values it found: one
[16-byte entry](../../home/architecture.md#node-index-of-json-views) per value (and one per object key), in document
order. Integers are converted while parsing and stored in their entry. Floating-point numbers and strings are
referenced in place in the source text: a float is converted when it is read, and only strings that contain escape
sequences are decoded, into one shared buffer owned by the document.

[`basic_json_view`](../../api/basic_json_view/index.md) is a small, trivially copyable handle (two pointers) into that
index. It gives you the read-only, type-inspection part of the `basic_json` interface —
[`type()`](../../api/basic_json_view/type.md) and the `is_*()` predicates,
[`size()`](../../api/basic_json_view/size.md)/[`empty()`](../../api/basic_json_view/empty.md) — as well as element
access ([`operator[]`](../../api/basic_json_view/operator%5B%5D.md), [`at`](../../api/basic_json_view/at.md),
[`front`](../../api/basic_json_view/front.md)/[`back`](../../api/basic_json_view/back.md)), lookup
([`find`](../../api/basic_json_view/find.md), [`contains`](../../api/basic_json_view/contains.md),
[`count`](../../api/basic_json_view/count.md)), and iteration
([`begin`](../../api/basic_json_view/begin.md)/[`end`](../../api/basic_json_view/end.md),
[`items`](../../api/basic_json_view/items.md)) — without ever allocating a `basic_json` value. When you do need an
actual `basic_json` value for a subtree, [`materialize()`](../../api/basic_json_view/materialize.md) builds exactly the
one [`parse()`](../../api/basic_json/parse.md) would have produced for it.

The same small text, parsed both ways:

<div class="nj-fig-wrap" markdown>
--8<-- "images/json_view_layout.svg"
</div>

<p class="nj-caption" markdown>Top: the tree of separate heap allocations that `basic_json::parse()` builds. Bottom: `json_document::parse()` keeps the source text and builds one flat index of 16-byte nodes that point back into it, plus a buffer of decoded strings.</p>

## How to use it

Include `<nlohmann/json_view.hpp>` in addition to (or instead of) `<nlohmann/json.hpp>`. Parse into a
[`json_document`](../../api/json_document.md), inspect its [`root()`](../../api/basic_json_document/root.md), and
`materialize()` when you need a real value. `materialize()` works on any view, not just the root, so you can turn just
the subtree you need into a value:

??? example "Example: parse a document, inspect its root, and materialize it"

    ```cpp
    --8<-- "examples/json_document.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/json_document.output"
    ```

[`ordered_json_document`](../../api/ordered_json_document.md) is the equivalent for
[`ordered_json`](../../api/ordered_json.md), just as [`ordered_json`](../../api/ordered_json.md) is to
[`json`](../../api/json.md).

A view behaves like a `basic_json` value in most respects, but not in all: lookups of a repeated key, the order in
which an object's members are visited, and what a missing key does to chained `operator[]` are the most visible
differences. [Differences from `basic_json`](differences.md) lists all of them.

## Where to go next

- [Ownership and lifetime](lifetime.md) - when a document borrows its source text, and how long a view stays valid
- [Differences from `basic_json`](differences.md) - everything a view does differently from a parsed `basic_json` value
- [Reading values](reading.md) - converting with `get<T>()`, reading strings and numbers without copying, and writing a
  view back with `dump()`
- [Writing generic code](generic_code.md) - functions and `from_json()` overloads that accept views
- [Editing a document](editing.md) - patching a document in place, keeping its member order and number spellings
- [Images](images.md) - saving a parsed document and loading it back without parsing

## Choosing between `json`, `ordered_json`, the SAX interface, and `json_view`

| | [`json`](../../api/json.md) / [`ordered_json`](../../api/ordered_json.md) | [SAX interface](../parsing/sax_interface.md) | [`json_document`](../../api/json_document.md) / [`json_view`](../../api/json_view.md) | [`json_editable_document`](../../api/json_editable_document.md) / [`json_editable_view`](../../api/json_editable_view.md) |
|---|---|---|---|---|
| **Ownership** | owns every value | owns nothing; you decide what to keep, in your handler | borrows or owns the *text*; the index is always owned by the document | same as `json_document`; edits go to storage the document owns |
| **Mutability** | freely mutable | not applicable (a one-shot event stream) | read-only | [`set`](../../api/basic_json_document/set.md)/[`push_back`](../../api/basic_json_document/push_back.md)/[`insert`](../../api/basic_json_document/insert.md)/[`erase`](../../api/basic_json_document/erase.md) edit in place; the source text is never rewritten |
| **What you get** | a full tree you can read, write, and keep as long as you like | a sequence of callbacks; whatever your handler builds from them | a flat index plus, on demand, [`materialize()`](../../api/basic_json_view/materialize.md)d `json`/`ordered_json` values for the parts you actually use | the same, plus [`dump()`](../../api/basic_json_view/dump.md) of an edited document that keeps the member order and, with [`number_format::source`](../../api/basic_json_view/number_format.md), the spelling of every untouched number |
| **Typical use** | general-purpose JSON handling: config, request/response bodies you build or modify, anything you hold onto | validating or projecting a text into your own data structure without ever holding the whole thing as JSON | large or high-volume input where you only need part of it, or need it repeatedly, and can keep the source text (or a copy) alive for as long as the document lives | a document you read, patch a few fields of, and write back — a configuration file, for instance — where the rest of it should come back exactly as it was |
| **Caching/reload** | not applicable — re-parse, or roll your own serialization | not applicable | [`save()`](../../api/basic_json_document/save.md)/[`load()`](../../api/basic_json_document/load.md): cache the parsed index as an [image](images.md) and reload it without parsing | same, saving the document's current — possibly edited — state |

<p class="nj-table-caption" markdown>Each column is one way to work with JSON in this library, and each row compares one property of them.</p>

## See also

- [`basic_json_document`](../../api/basic_json_document/index.md) - the document that owns the parsed index (parse, access, images, edits)
- [`basic_json_view`](../../api/basic_json_view/index.md) - the non-owning handle to a value in a document
- [`json_document`](../../api/json_document.md) - and [`ordered_json_document`](../../api/ordered_json_document.md) - the read-only documents
- [`json_editable_document`](../../api/json_editable_document.md) - and [`ordered_json_editable_document`](../../api/ordered_json_editable_document.md) - the documents that can be edited in place
- [Architecture](../../home/architecture.md#node-index-of-json-views) - the layout of the node index
- [SAX interface](../parsing/sax_interface.md) - event-based parsing without building a tree
- [Performance](../performance.md) - benchmarks and tuning of parsing and serialization
- [Large, Streamed, and Partial Input](../parsing/large_and_partial_input.md) - reading only the part of a text you need

## Version history

- Added in version 3.13.0.
