# <small>nlohmann::</small>basic_json_document

<small>Defined in header `<nlohmann/json_view.hpp>`</small>

```cpp
template<typename BasicJsonType>
class basic_json_document;
```

A parsed JSON text, held as a flat index of its values
([16 bytes per value](../../home/architecture.md#node-index-of-json-views)) instead of a tree of `BasicJsonType` values.
Strings and numbers stay in the source text; only strings that contain escapes are decoded, into one buffer owned by
the document. [`basic_json_view`](../basic_json_view/index.md) is a read-only handle to one value of a
`basic_json_document`; [`materialize()`](../basic_json_view/materialize.md) turns a subtree back into the
`BasicJsonType` value that [`BasicJsonType::parse()`](../basic_json/parse.md) would have produced for it.

A document may **borrow** the text it was parsed from (the caller's buffer must then outlive the document) or **own**
it (a copy, or an rvalue `#!cpp std::string` that was moved in); see [`owns_source`](owns_source.md). `basic_json_document`
is move-only: copying a document would either duplicate a potentially large index and text, or leave two documents
claiming to borrow the same buffer, so it is disabled.

## Template parameters

`BasicJsonType`
:   a specialization of [`basic_json`](../basic_json/index.md), for instance [`json`](../json.md) or
    [`ordered_json`](../ordered_json.md). Only 64-bit `number_integer_t`/`number_unsigned_t` types are supported; this
    is checked with a `static_assert`.

## Specializations

- [**json_document**](../json_document.md) - documents of the default specialization [`json`](../json.md)
- [**ordered_json_document**](../ordered_json_document.md) - documents of [`ordered_json`](../ordered_json.md)

## Member types

- **view_type** - the type of view returned by [`root()`](root.md) (`#!cpp basic_json_view<BasicJsonType>`)
- **value_t** - the JSON type enumeration, see [`basic_json::value_t`](../basic_json/value_t.md)

## Member functions

- [(constructor)](basic_json_document.md)
- [**parse**](parse.md) (_static_) - deserialize from a compatible input, borrowing or owning it as appropriate
- [**parse_copy**](parse_copy.md) (_static_) - deserialize a copy of a compatible input
- [**accept**](accept.md) (_static_) - check whether the input is valid JSON
- [**read**](read.md) - (re-)parse into this document, reusing its memory
- [**root**](root.md) - the view of the root value
- [**is_discarded**](is_discarded.md) - return whether the last parse failed
- [**source**](source.md) - the parsed text
- [**owns_source**](owns_source.md) - return whether the document holds its own copy of the text
- [**node_count**](node_count.md) - the number of index entries (values plus object keys)
- [**memory_usage**](memory_usage.md) - the number of bytes held by the document
- [**shrink_to_fit**](shrink_to_fit.md) - release unused index capacity

## Version history

- Added in version 3.13.0.
