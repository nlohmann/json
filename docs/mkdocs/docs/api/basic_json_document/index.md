# <small>nlohmann::</small>basic_json_document

<small>Defined in header `<nlohmann/json_view.hpp>`</small>

```cpp
template<typename BasicJsonType, bool Editable = false>
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

With `#!cpp Editable == true`, the document also offers [`set`](set.md), [`push_back`](push_back.md),
[`insert`](insert.md), and [`erase`](erase.md) to change values in place, see [Edits](#edits) below. The source text
itself is never written; a read-only document (`#!cpp Editable == false`, the default) does not carry any of the
bookkeeping edits need, and calling any of them on one fails to compile (`#!cpp static_assert`).

## Template parameters

`BasicJsonType`
:   a specialization of [`basic_json`](../basic_json/index.md), for instance [`json`](../json.md) or
    [`ordered_json`](../ordered_json.md). Only 64-bit `number_integer_t`/`number_unsigned_t` types are supported; this
    is checked with a `static_assert`.

`Editable`
:   whether the document supports [`set`](set.md), [`push_back`](push_back.md), [`insert`](insert.md), and
    [`erase`](erase.md) (optional, `#!cpp false` by default). See [Edits](#edits) below.

## Specializations

- [**json_document**](../json_document.md) - read-only documents of the default specialization [`json`](../json.md)
- [**ordered_json_document**](../ordered_json_document.md) - read-only documents of
  [`ordered_json`](../ordered_json.md)
- [**json_editable_document**](../json_editable_document.md) - editable documents of [`json`](../json.md)
- [**ordered_json_editable_document**](../ordered_json_editable_document.md) - editable documents of
  [`ordered_json`](../ordered_json.md)

## Member types

- **view_type** - the type of view returned by [`root()`](root.md) (`#!cpp basic_json_view<BasicJsonType, Editable>`)
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
- [**set**](set.md) - replace a value, or set an object member, an array element, or the value a JSON pointer refers
  to (`#!cpp Editable` documents only)
- [**push_back**](push_back.md) - append to an array (`#!cpp Editable` documents only)
- [**insert**](insert.md) - insert an element into an array before a given position (`#!cpp Editable` documents only)
- [**erase**](erase.md) - remove an object member, an array element, or the value a JSON pointer refers to
  (`#!cpp Editable` documents only)

## Edits

An editable document (`#!cpp Editable == true`) can be changed after parsing, with [`set`](set.md),
[`push_back`](push_back.md), [`insert`](insert.md), and [`erase`](erase.md);
[`json_editable_document`](../json_editable_document.md) and
[`ordered_json_editable_document`](../ordered_json_editable_document.md) are the corresponding specializations. A few
points apply to every edit:

- **The source text is never written**, and the parsed index never moves: every value keeps the node it was parsed
  into, so [views](../basic_json_view/index.md) taken before an edit stay valid, including
  [`root()`](root.md). New values (and the element sequences of an edited array/object) go to storage owned by the
  document, allocated on demand.
- **A view keeps referring to the same value.** After [`set`](set.md) replaces the value a view refers to, that view
  sees the new value; a view of a value that a later edit replaces or drops keeps showing what it last held. An edit
  of an array or object, however, **invalidates the iterators taken over it** (its members may now live in a
  different sequence), and a string obtained with [`get_string()`](../basic_json_view/get_string.md) stays valid even
  as further edits happen (earlier buffers of edited text are kept alive, not overwritten).
- **Values are accepted three ways:** a [`basic_json_view`](../basic_json_view/index.md) of *any* document
  (read-only or editable; it is copied, nothing is shared with the source document), a `BasicJsonType` value, or
  anything `BasicJsonType` can be constructed from (numbers, strings, `#!cpp bool`, `#!cpp nullptr`, containers, ...).
- [`dump()`](../basic_json_view/dump.md) writes an edited document with members in document order, new members at
  the end, and, with [`number_format::source`](../basic_json_view/number_format.md), keeps the spelling of every
  number that was not itself edited -- see [Editing a document](../../features/json_view.md#editing-a-document) for
  why this matters.
- [`read()`](read.md) discards all edits, [`shrink_to_fit()`](shrink_to_fit.md) does not move the node index once
  there are edits, and [`memory_usage()`](memory_usage.md) includes the memory edits use.
  [`source_offset()`](../basic_json_view/source_offset.md) of a value introduced by an edit is
  `#!cpp static_cast<std::size_t>(-1)`, the same value it reports for a decoded string.

## Version history

- Added in version 3.13.0.
