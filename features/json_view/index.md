# Zero-copy JSON views

`<nlohmann/json_view.hpp>` adds a read-only, non-owning way to look at a parsed JSON text, as an alternative to building a [`basic_json`](https://json.nlohmann.me/api/basic_json/index.md) tree with [`parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md).

## The problem

[`basic_json::parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md) builds a tree of `basic_json` values: one allocation for every array and object, and every string copied into its own `std::string`. That is the right trade-off when the program goes on to read and write the value freely, but it does more work than necessary when only a small part of a large JSON text is actually needed, or when the same text is parsed over and over (many small messages, for instance) and most of the resulting tree is thrown away almost immediately.

## The idea

[`basic_json_document::parse()`](https://json.nlohmann.me/api/basic_json_document/parse/index.md) parses the same JSON grammar, with the same options, but instead of a tree it builds a flat index of the values it found: one [16-byte entry](https://json.nlohmann.me/home/architecture/#node-index-of-json-views) per value (and one per object key), in document order. Integers are converted while parsing and stored in their entry. Floating-point numbers and strings are referenced in place in the source text: a float is converted when it is read, and only strings that contain escape sequences are decoded, into one shared buffer owned by the document.

[`basic_json_view`](https://json.nlohmann.me/api/basic_json_view/index.md) is a small, trivially copyable handle (two pointers) into that index. It gives you the read-only, type-inspection part of the `basic_json` interface — [`type()`](https://json.nlohmann.me/api/basic_json_view/type/index.md) and the `is_*()` predicates, [`size()`](https://json.nlohmann.me/api/basic_json_view/size/index.md)/[`empty()`](https://json.nlohmann.me/api/basic_json_view/empty/index.md) — as well as element access ([`operator[]`](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/index.md), [`at`](https://json.nlohmann.me/api/basic_json_view/at/index.md), [`front`](https://json.nlohmann.me/api/basic_json_view/front/index.md)/[`back`](https://json.nlohmann.me/api/basic_json_view/back/index.md)), lookup ([`find`](https://json.nlohmann.me/api/basic_json_view/find/index.md), [`contains`](https://json.nlohmann.me/api/basic_json_view/contains/index.md), [`count`](https://json.nlohmann.me/api/basic_json_view/count/index.md)), and iteration ([`begin`](https://json.nlohmann.me/api/basic_json_view/begin/index.md)/[`end`](https://json.nlohmann.me/api/basic_json_view/end/index.md), [`items`](https://json.nlohmann.me/api/basic_json_view/items/index.md)) — without ever allocating a `basic_json` value. When you do need an actual `basic_json` value for a subtree, [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) builds exactly the one [`parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md) would have produced for it.

The same small text, parsed both ways:

Top: the tree of separate heap allocations that `basic_json::parse()` builds. Bottom: `json_document::parse()` keeps the source text and builds one flat index of 16-byte nodes that point back into it, plus a buffer of decoded strings.

## How to use it

Include `<nlohmann/json_view.hpp>` in addition to (or instead of) `<nlohmann/json.hpp>`. Parse into a [`json_document`](https://json.nlohmann.me/api/json_document/index.md), inspect its [`root()`](https://json.nlohmann.me/api/basic_json_document/root/index.md), and `materialize()` when you need a real value. `materialize()` works on any view, not just the root, so you can turn just the subtree you need into a value:

Example: parse a document, inspect its root, and materialize it

```
#include <iostream>
#include <nlohmann/json_view.hpp>

using nlohmann::json_document;

int main()
{
    std::cout << std::boolalpha;

    // json_document is basic_json_document<nlohmann::json>: same value types
    // and containers as the ordinary json specialization
    json_document doc = json_document::parse(R"({"pi": 3.14, "numbers": [1, 2, 3]})");

    std::cout << doc.root().is_object() << '\n';
    std::cout << doc.root().materialize().dump() << '\n';
}
```

Output:

```
true
{"numbers":[1,2,3],"pi":3.14}
```

[`ordered_json_document`](https://json.nlohmann.me/api/ordered_json_document/index.md) is the equivalent for [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md), just as [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md) is to [`json`](https://json.nlohmann.me/api/json/index.md).

A view behaves like a `basic_json` value in most respects, but not in all: lookups of a repeated key, the order in which an object's members are visited, and what a missing key does to chained `operator[]` are the most visible differences. [Differences from `basic_json`](https://json.nlohmann.me/features/json_view/differences/index.md) lists all of them.

## Where to go next

- [Ownership and lifetime](https://json.nlohmann.me/features/json_view/lifetime/index.md) - when a document borrows its source text, and how long a view stays valid
- [Differences from `basic_json`](https://json.nlohmann.me/features/json_view/differences/index.md) - everything a view does differently from a parsed `basic_json` value
- [Reading values](https://json.nlohmann.me/features/json_view/reading/index.md) - converting with `get<T>()`, reading strings and numbers without copying, and writing a view back with `dump()`
- [Writing generic code](https://json.nlohmann.me/features/json_view/generic_code/index.md) - functions and `from_json()` overloads that accept views
- [Editing a document](https://json.nlohmann.me/features/json_view/editing/index.md) - patching a document in place, keeping its member order and number spellings
- [Images](https://json.nlohmann.me/features/json_view/images/index.md) - saving a parsed document and loading it back without parsing

## Choosing between `json`, `ordered_json`, the SAX interface, and `json_view`

|                    | [`json`](https://json.nlohmann.me/api/json/index.md) / [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md) | [SAX interface](https://json.nlohmann.me/features/parsing/sax_interface/index.md)                         | [`json_document`](https://json.nlohmann.me/api/json_document/index.md) / [`json_view`](https://json.nlohmann.me/api/json_view/index.md)                                                                                                                                                | [`json_editable_document`](https://json.nlohmann.me/api/json_editable_document/index.md) / [`json_editable_view`](https://json.nlohmann.me/api/json_editable_view/index.md)                                                                                                                                                                                         |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Ownership**      | owns every value                                                                                                            | owns nothing; you decide what to keep, in your handler                                                    | borrows or owns the *text*; the index is always owned by the document                                                                                                                                                                                                                  | same as `json_document`; edits go to storage the document owns                                                                                                                                                                                                                                                                                                      |
| **Mutability**     | freely mutable                                                                                                              | not applicable (a one-shot event stream)                                                                  | read-only                                                                                                                                                                                                                                                                              | [`set`](https://json.nlohmann.me/api/basic_json_document/set/index.md)/[`push_back`](https://json.nlohmann.me/api/basic_json_document/push_back/index.md)/[`insert`](https://json.nlohmann.me/api/basic_json_document/insert/index.md)/[`erase`](https://json.nlohmann.me/api/basic_json_document/erase/index.md) edit in place; the source text is never rewritten |
| **What you get**   | a full tree you can read, write, and keep as long as you like                                                               | a sequence of callbacks; whatever your handler builds from them                                           | a flat index plus, on demand, [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md)d `json`/`ordered_json` values for the parts you actually use                                                                                                        | the same, plus [`dump()`](https://json.nlohmann.me/api/basic_json_view/dump/index.md) of an edited document that keeps the member order and, with [`number_format::source`](https://json.nlohmann.me/api/basic_json_view/number_format/index.md), the spelling of every untouched number                                                                            |
| **Typical use**    | general-purpose JSON handling: config, request/response bodies you build or modify, anything you hold onto                  | validating or projecting a text into your own data structure without ever holding the whole thing as JSON | large or high-volume input where you only need part of it, or need it repeatedly, and can keep the source text (or a copy) alive for as long as the document lives                                                                                                                     | a document you read, patch a few fields of, and write back — a configuration file, for instance — where the rest of it should come back exactly as it was                                                                                                                                                                                                           |
| **Caching/reload** | not applicable — re-parse, or roll your own serialization                                                                   | not applicable                                                                                            | [`save()`](https://json.nlohmann.me/api/basic_json_document/save/index.md)/[`load()`](https://json.nlohmann.me/api/basic_json_document/load/index.md): cache the parsed index as an [image](https://json.nlohmann.me/features/json_view/images/index.md) and reload it without parsing | same, saving the document's current — possibly edited — state                                                                                                                                                                                                                                                                                                       |

Each column is one way to work with JSON in this library, and each row compares one property of them.

## See also

- [`basic_json_document`](https://json.nlohmann.me/api/basic_json_document/index.md) - the document that owns the parsed index (parse, access, images, edits)
- [`basic_json_view`](https://json.nlohmann.me/api/basic_json_view/index.md) - the non-owning handle to a value in a document
- [`json_document`](https://json.nlohmann.me/api/json_document/index.md) - and [`ordered_json_document`](https://json.nlohmann.me/api/ordered_json_document/index.md) - the read-only documents
- [`json_editable_document`](https://json.nlohmann.me/api/json_editable_document/index.md) - and [`ordered_json_editable_document`](https://json.nlohmann.me/api/ordered_json_editable_document/index.md) - the documents that can be edited in place
- [Architecture](https://json.nlohmann.me/home/architecture/#node-index-of-json-views) - the layout of the node index
- [SAX interface](https://json.nlohmann.me/features/parsing/sax_interface/index.md) - event-based parsing without building a tree
- [Performance](https://json.nlohmann.me/features/performance/index.md) - benchmarks and tuning of parsing and serialization
- [Large, Streamed, and Partial Input](https://json.nlohmann.me/features/parsing/large_and_partial_input/index.md) - reading only the part of a text you need

## Version history

- Added in version 3.13.0 unreleased.
