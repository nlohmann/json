# nlohmann::basic_json_document

Defined in header `<nlohmann/json_view.hpp>`

```
template<typename BasicJsonType, bool Editable = false>
class basic_json_document;
```

A parsed JSON text, held as a flat index of its values ([16 bytes per value](https://json.nlohmann.me/home/architecture/#node-index-of-json-views)) instead of a tree of `BasicJsonType` values. Strings and numbers stay in the source text; only strings that contain escapes are decoded, into one buffer owned by the document. [`basic_json_view`](https://json.nlohmann.me/api/basic_json_view/index.md) is a read-only handle to one value of a `basic_json_document`; [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) turns a subtree into the `BasicJsonType` value that [`BasicJsonType::parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md) would have produced for it.

A document may **borrow** the text it was parsed from (the caller's buffer must then outlive the document) or **own** it (a copy, or an rvalue `std::string` that was moved in); see [`owns_source`](https://json.nlohmann.me/api/basic_json_document/owns_source/index.md). `basic_json_document` is move-only: a copy would duplicate the whole index, the decoded-string buffer, and the owned text, and a move is enough in every use we know of. The index, the decoded strings, and the owned text live in one heap block that the document holds through a `std::unique_ptr`; this is also why views survive a move of the document.

With `Editable == true`, the document also offers [`set`](https://json.nlohmann.me/api/basic_json_document/set/index.md), [`push_back`](https://json.nlohmann.me/api/basic_json_document/push_back/index.md), [`insert`](https://json.nlohmann.me/api/basic_json_document/insert/index.md), and [`erase`](https://json.nlohmann.me/api/basic_json_document/erase/index.md) to change values in place, see [Edits](#edits) below. The source text itself is never written; a read-only document (`Editable == false`, the default) does not carry any of the bookkeeping edits need, and calling any of them on one fails to compile (`static_assert`).

## Template parameters

`BasicJsonType` : a specialization of [`basic_json`](https://json.nlohmann.me/api/basic_json/index.md), for instance [`json`](https://json.nlohmann.me/api/json/index.md) or [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md). Only 64-bit `number_integer_t`/`number_unsigned_t` types are supported; this is checked with a `static_assert`.

`Editable` : whether the document supports [`set`](https://json.nlohmann.me/api/basic_json_document/set/index.md), [`push_back`](https://json.nlohmann.me/api/basic_json_document/push_back/index.md), [`insert`](https://json.nlohmann.me/api/basic_json_document/insert/index.md), and [`erase`](https://json.nlohmann.me/api/basic_json_document/erase/index.md) (optional, `false` by default). See [Edits](#edits) below.

## Specializations

- [**json_document**](https://json.nlohmann.me/api/json_document/index.md) - read-only documents of the default specialization [`json`](https://json.nlohmann.me/api/json/index.md)
- [**ordered_json_document**](https://json.nlohmann.me/api/ordered_json_document/index.md) - read-only documents of [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md)
- [**json_editable_document**](https://json.nlohmann.me/api/json_editable_document/index.md) - editable documents of [`json`](https://json.nlohmann.me/api/json/index.md)
- [**ordered_json_editable_document**](https://json.nlohmann.me/api/ordered_json_editable_document/index.md) - editable documents of [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md)

## Member types

- **view_type** - the type of view returned by [`root()`](https://json.nlohmann.me/api/basic_json_document/root/index.md) (`basic_json_view<BasicJsonType, Editable>`)
- **value_t** - the JSON type enumeration, see [`basic_json::value_t`](https://json.nlohmann.me/api/basic_json/value_t/index.md)
- **image_check** - how [`load()`](https://json.nlohmann.me/api/basic_json_document/load/index.md) validates an image (`full`, `bounds`, `none`), see [`image_check`](https://json.nlohmann.me/api/basic_json_document/load/#image_check)

## Member functions

- [(constructor)](https://json.nlohmann.me/api/basic_json_document/basic_json_document/index.md)

### Parsing

- [**parse**](https://json.nlohmann.me/api/basic_json_document/parse/index.md) (*static*) - deserialize from a compatible input, borrowing or owning it as appropriate
- [**parse_copy**](https://json.nlohmann.me/api/basic_json_document/parse_copy/index.md) (*static*) - deserialize a copy of a compatible input
- [**accept**](https://json.nlohmann.me/api/basic_json_document/accept/index.md) (*static*) - check whether the input is valid JSON
- [**read**](https://json.nlohmann.me/api/basic_json_document/read/index.md) - (re-)parse into this document, reusing its memory

### Access

- [**root**](https://json.nlohmann.me/api/basic_json_document/root/index.md) - the view of the root value
- [**is_discarded**](https://json.nlohmann.me/api/basic_json_document/is_discarded/index.md) - return whether the last parse failed
- [**source**](https://json.nlohmann.me/api/basic_json_document/source/index.md) - the parsed text
- [**owns_source**](https://json.nlohmann.me/api/basic_json_document/owns_source/index.md) - return whether the document holds its own copy of the text
- [**node_count**](https://json.nlohmann.me/api/basic_json_document/node_count/index.md) - the number of index entries (values plus object keys)
- [**memory_usage**](https://json.nlohmann.me/api/basic_json_document/memory_usage/index.md) - the number of bytes held by the document
- [**shrink_to_fit**](https://json.nlohmann.me/api/basic_json_document/shrink_to_fit/index.md) - release unused index capacity

### Images

- [**save**](https://json.nlohmann.me/api/basic_json_document/save/index.md) - the document as an image that `load()` reads without parsing
- [**load**](https://json.nlohmann.me/api/basic_json_document/load/index.md) (*static*) - read an image written by `save()`

### Edits

- [**set**](https://json.nlohmann.me/api/basic_json_document/set/index.md) - replace a value, or set an object member, an array element, or the value a JSON pointer refers to (`Editable` documents only)
- [**push_back**](https://json.nlohmann.me/api/basic_json_document/push_back/index.md) - append to an array (`Editable` documents only)
- [**insert**](https://json.nlohmann.me/api/basic_json_document/insert/index.md) - insert an element into an array before a given position (`Editable` documents only)
- [**erase**](https://json.nlohmann.me/api/basic_json_document/erase/index.md) - remove an object member, an array element, or the value a JSON pointer refers to (`Editable` documents only)

## Edits

An editable document (`Editable == true`) can be changed after parsing, with [`set`](https://json.nlohmann.me/api/basic_json_document/set/index.md), [`push_back`](https://json.nlohmann.me/api/basic_json_document/push_back/index.md), [`insert`](https://json.nlohmann.me/api/basic_json_document/insert/index.md), and [`erase`](https://json.nlohmann.me/api/basic_json_document/erase/index.md); [`json_editable_document`](https://json.nlohmann.me/api/json_editable_document/index.md) and [`ordered_json_editable_document`](https://json.nlohmann.me/api/ordered_json_editable_document/index.md) are the corresponding specializations. A few points apply to every edit:

- **The source text is never written**, and the parsed index never moves: every value keeps the node it was parsed into, so [views](https://json.nlohmann.me/api/basic_json_view/index.md) taken before an edit stay valid, including [`root()`](https://json.nlohmann.me/api/basic_json_document/root/index.md). New values (and the element sequences of an edited array/object) go to storage owned by the document, allocated on demand.
- **A view keeps referring to the same value.** After [`set`](https://json.nlohmann.me/api/basic_json_document/set/index.md) replaces the value a view refers to, that view sees the new value; a view of a value that a later edit replaces or drops keeps showing what it last held. An edit of an array or object, however, **invalidates the iterators taken over it** (its members may now live in a different sequence), and a string obtained with [`get_string()`](https://json.nlohmann.me/api/basic_json_view/get_string/index.md) stays valid even as further edits happen (earlier buffers of edited text are kept alive, not overwritten).
- **Values are accepted three ways:** a [`basic_json_view`](https://json.nlohmann.me/api/basic_json_view/index.md) of *any* document (read-only or editable; it is copied, nothing is shared with the source document), a `BasicJsonType` value, or anything `BasicJsonType` can be constructed from (numbers, strings, `bool`, `nullptr`, containers, ...).
- [`dump()`](https://json.nlohmann.me/api/basic_json_view/dump/index.md) writes an edited document with members in document order, new members at the end, and, with [`number_format::source`](https://json.nlohmann.me/api/basic_json_view/number_format/index.md), keeps the spelling of every number that was not itself edited -- see [Editing a document](https://json.nlohmann.me/features/json_view/#editing-a-document) for why this matters.
- [`read()`](https://json.nlohmann.me/api/basic_json_document/read/index.md) discards all edits, [`shrink_to_fit()`](https://json.nlohmann.me/api/basic_json_document/shrink_to_fit/index.md) does not move the node index once there are edits, and [`memory_usage()`](https://json.nlohmann.me/api/basic_json_document/memory_usage/index.md) includes the memory edits use. [`source_offset()`](https://json.nlohmann.me/api/basic_json_view/source_offset/index.md) of a value introduced by an edit is `static_cast<std::size_t>(-1)`, the same value it reports for a decoded string.

## See also

- [Zero-copy JSON views](https://json.nlohmann.me/features/json_view/index.md) - guide to documents and views
- [**basic_json_view**](https://json.nlohmann.me/api/basic_json_view/index.md) - the non-owning handle to a value in a document
- [**json_document**](https://json.nlohmann.me/api/json_document/index.md) and [**json_editable_document**](https://json.nlohmann.me/api/json_editable_document/index.md) - the default specializations
- [**materialize**](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) - build a `basic_json` value from a view

## Version history

- Added in version 3.13.0 unreleased.
