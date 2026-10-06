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
[`size()`](../api/basic_json_view/size.md)/[`empty()`](../api/basic_json_view/empty.md) -- as well as element access
([`operator[]`](../api/basic_json_view/operator%5B%5D.md), [`at`](../api/basic_json_view/at.md),
[`front`](../api/basic_json_view/front.md)/[`back`](../api/basic_json_view/back.md)), lookup
([`find`](../api/basic_json_view/find.md), [`contains`](../api/basic_json_view/contains.md),
[`count`](../api/basic_json_view/count.md)), and iteration
([`begin`](../api/basic_json_view/begin.md)/[`end`](../api/basic_json_view/end.md),
[`items`](../api/basic_json_view/items.md)) -- without ever allocating a `basic_json` value. When you do need an
actual `basic_json` value for a subtree, [`materialize()`](../api/basic_json_view/materialize.md) builds exactly the
one [`parse()`](../api/basic_json/parse.md) would have produced for it.

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
- **Objects iterate in document order.** [`begin()`](../api/basic_json_view/begin.md)/
  [`end()`](../api/basic_json_view/end.md) and [`items()`](../api/basic_json_view/items.md) visit an object's
  members in the order they appear in the source text. `basic_json`'s default `object_t` is a `std::map`, which
  sorts by key, so iterating a [`materialize()`](../api/basic_json_view/materialize.md)d value can print members in
  a different order than iterating the view they came from.
- **Duplicate keys are visible.** If an object in the source text repeats a key,
  [`begin()`](../api/basic_json_view/begin.md)/[`end()`](../api/basic_json_view/end.md) and
  [`items()`](../api/basic_json_view/items.md) visit *every* occurrence (and [`size()`](../api/basic_json_view/size.md)
  counts all of them), while [`operator[]`](../api/basic_json_view/operator%5B%5D.md),
  [`at`](../api/basic_json_view/at.md), [`find`](../api/basic_json_view/find.md),
  [`contains`](../api/basic_json_view/contains.md), and [`count`](../api/basic_json_view/count.md) resolve to the
  *first* occurrence, since a lookup can stop as soon as it finds a match. `basic_json::parse()` (and so
  [`materialize()`](../api/basic_json_view/materialize.md)) instead keeps only the *last* value for a repeated key.
  See the [Notes on duplicate keys](../api/basic_json_view/operator%5B%5D.md#notes) of `operator[]`.
- **No [`JSON_DIAGNOSTICS`](../api/macros/json_diagnostics.md) path.** Exceptions thrown by `basic_json_view`'s own
  element access and lookup functions never carry the JSON Pointer path `JSON_DIAGNOSTICS` would otherwise add: the
  view has no `basic_json` value to point at, so the exception is created without one, regardless of how
  `BasicJsonType` was built.
- **Ordering comparisons are not provided** by `basic_json_view` -- there is no `#!cpp operator<`.
  [`operator==`](../api/basic_json_view/operator_eq.md) and [`operator!=`](../api/basic_json_view/operator_ne.md) are
  provided, though: two views, or a view and a `BasicJsonType` value, compare equal exactly when
  [`materialize()`](../api/basic_json_view/materialize.md) or [`parse()`](../api/basic_json/parse.md) would produce
  equal values for them, without ever building a tree to do it. For ordering, too,
  [`materialize()`](../api/basic_json_view/materialize.md) is the way to get a value you can compare.

## Getting values out without copying

[`get<T>()`](../api/basic_json_view/get.md) converts many `T` directly from the flat index, without ever building a
`basic_json` value for the conversion: `#!cpp bool`, arithmetic types, `#!cpp std::nullptr_t`,
`#!cpp std::string`/other `#!cpp std::basic_string`s (copied once), `basic_json`/`ordered_json` (via
[`materialize()`](../api/basic_json_view/materialize.md)), `basic_json_view` itself, `#!cpp std::vector<U>`, and
`#!cpp std::map`/`#!cpp std::unordered_map` with string-like keys. Every other type -- `#!cpp std::list`,
`#!cpp std::pair`, `#!cpp std::array`, enumerations, user types with a `from_json()` -- goes through
[`materialize()`](../api/basic_json_view/materialize.md)`.get<T>()` instead: the subtree is built into a real
`basic_json` value first, exactly as [`parse()`](../api/basic_json/parse.md) would, and converted from there.

Two conversions never copy at all:

- [`get_string()`](../api/basic_json_view/get_string.md) (equivalently, `#!cpp get<string_view_t>()`) returns a
  string as a `string_view_t` pointing into the document's [`source()`](../api/basic_json_document/source.md) text --
  or, for a string that contains escape sequences, into the document's own buffer of decoded strings -- instead of
  allocating a new `#!cpp std::string`.
- [`number_token()`](../api/basic_json_view/number_token.md) returns a number exactly as it was written in the
  source, e.g. `#!cpp "1.50"`, `#!cpp "1E2"`, or an integer with more digits than any number type holds, instead of
  rounding it into a `#!cpp double`/`#!cpp int64_t` the way `#!cpp get<T>()` (and
  [`basic_json::parse()`](../api/basic_json/parse.md)) would.

Both results are only valid as long as the view -- and, for a string with no escapes, the borrowed source text -- is.

## Writing a view back

[`dump()`](../api/basic_json_view/dump.md) serializes a view directly from the flat index, without ever building a
`basic_json` value. An object's members are written in document order, not sorted by key, and *every* occurrence of a
repeated key is written, not only the last one -- the same two ways [iteration](#what-is-different) already differs
from a [`materialize()`](../api/basic_json_view/materialize.md)d value, see above. `#!cpp materialize().dump()` gives
a different result in both respects for a `json_view`.

By default, numbers are written the way [`basic_json::dump()`](../api/basic_json/dump.md) would.
[`number_format::source`](../api/basic_json_view/number_format.md) instead copies every number exactly as it was
written in the source text -- a price like `#!cpp 19.90`, a long order or account ID with more digits than any number
type holds, or a high-precision coordinate -- something `basic_json` cannot do at all, since parsing already reduces
a number to its parsed `#!cpp double`/`#!cpp int64_t` value.

[`operator<<`](../api/basic_json_view/operator_ltlt.md) writes a view to a stream the way `basic_json`'s does, using
the stream's `width`/`fill` for indentation.

## Editing a document

Everything above is read-only: a `json_document`/`json_view` lets you look at a parsed text without copying it, but
not change it. [`basic_json_document<BasicJsonType, true>`](../api/basic_json_document/index.md) -- more conveniently
spelled [`json_editable_document`](../api/json_editable_document.md) or
[`ordered_json_editable_document`](../api/ordered_json_editable_document.md) -- also lets you
[`set`](../api/basic_json_document/set.md) a value, [`push_back`](../api/basic_json_document/push_back.md) onto or
[`insert`](../api/basic_json_document/insert.md) into an array, and [`erase`](../api/basic_json_document/erase.md)
an object member or an array element, still without ever building a `basic_json` tree for parts you do not touch.

`#!cpp Editable` defaults to `#!cpp false`, so `json_document`/`ordered_json_document` are unaffected -- they carry
none of the bookkeeping edits need, and calling `set`/`push_back`/`insert`/`erase` on one is a compile error, not a
runtime one.

### Why: editing without reformatting

The `#!cpp 19.90` price from [above](#writing-a-view-back) is exactly the kind of value that makes editing a `json`
or `ordered_json` value in place lossy. Say you parse a configuration file, patch one field, and write it back:

- **`json`** re-sorts every key on the way in (`object_t` is a `#!cpp std::map`) and rewrites every number to its
  shortest round-trip form on the way out -- a one-field patch turns into a diff that reorders the whole file and
  rewrites `#!cpp 19.90` to `#!cpp 19.9`.
- **`ordered_json`** keeps the key order, but still rewrites every number the same way: parsing has already reduced
  it to a `#!cpp double`/`#!cpp int64_t`, and there is no way back to how it was spelled in the source text.

An editable document keeps both. [`dump()`](../api/basic_json_view/dump.md) of an edited document writes members in
document order -- a member [`set`](../api/basic_json_document/set.md) added goes at the end, exactly where it was
inserted, and an [`erase`](../api/basic_json_document/erase.md)d member simply leaves a gap: everything around it
keeps its place -- and [`number_format::source`](../api/basic_json_view/number_format.md) keeps the exact spelling
of every number an edit did not itself touch; a number an edit *did* touch is written the way
[`BasicJsonType::dump()`](../api/basic_json/dump.md) would write it, since there is no source spelling for a brand
new value.

??? example "Example: patch a configuration, keeping member order and number spellings"

    ```cpp
    --8<-- "examples/json_editable_document.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/json_editable_document.output"
    ```

### What stays valid, and what an edit costs

The source text itself is **never written**, and the parsed index never moves -- a value keeps the node it was
parsed into for as long as it is not itself replaced. So every [view](../api/basic_json_view/index.md) taken before
an edit, including a previously obtained [`root()`](../api/basic_json_document/root.md), stays valid and, if it
still refers to the edited value, sees the edit; a view of a value a later edit drops or replaces just keeps showing
what it last held. New values go to storage the document allocates and owns on demand. The one thing an edit does
invalidate is the **iterators** taken over an edited array or object: the first time one of its elements is set,
appended to, inserted into, or erased, its elements move from the parsed, fixed layout to a growable block of links
so that [`push_back`](../api/basic_json_document/push_back.md) can later grow it in amortized constant time --
existing elements are not touched, but an iterator that was walking the old layout no longer matches. A string
obtained with
[`get_string()`](../api/basic_json_view/get_string.md) is unaffected either way and stays valid across further
edits. See [`basic_json_document`'s Edits](../api/basic_json_document/index.md#edits) for the details, and
[`set`'s Exception safety](../api/basic_json_document/set.md#exception-safety) for what an edit guarantees if it
throws (the *basic* guarantee, not the strong one `dump()` and the read-only functions provide). How edits are kept in
the index is described in the [architecture overview](../home/architecture.md#node-index-of-json-views).

## Images

[`save()`](../api/basic_json_document/save.md) writes a document as an *image*: a byte buffer that
[`load()`](../api/basic_json_document/load.md) reads back into a document without parsing -- no lexing, no building
the node index, nothing but copying the nodes and pointing the text and the decoded strings at the image. Where
[`parse_copy()`](../api/basic_json_document/parse_copy.md) still has to scan the whole input,
[`load()`](../api/basic_json_document/load.md) turns that scan into a copy of the node index alone.

**Why.** A document that is parsed once and then read many times -- a configuration loaded at startup, a template
rendered on every request, a large reference dataset a worker process needs in memory -- pays for parsing once but
can amortize [`save()`](../api/basic_json_document/save.md)'s cost across every later load. That makes images useful
for a cache: save a document the first time it is parsed (to a file, a shared-memory segment, an in-process cache),
and [`load()`](../api/basic_json_document/load.md) it on every later use instead of parsing the source text again.
They are just as useful for handing a parsed document to another process (or a forked worker) running the same build
of the library, since [`load()`](../api/basic_json_document/load.md) turns the transfer into a copy of the node index
plus pointers into the received bytes, not a re-parse.

**Choosing a check.** [`load()`](../api/basic_json_document/load.md) takes an
[`image_check`](../api/basic_json_document/load.md#image_check) that trades validation against speed:
`image_check::full` (the default) checks everything the parser itself guarantees, so a checked image is exactly as
safe to read and serialize as a freshly parsed document -- the right choice whenever the image did not come straight
from this process's own [`save()`](../api/basic_json_document/save.md), such as a file or a network peer.
`image_check::bounds` only checks structure and bounds -- cheaper, since it skips scanning the text and the decoded
strings -- and fits a cache the process trusts, one it wrote and reads back itself. `image_check::none` skips
validation entirely, for an image trusted as much as the process's own memory. See
[`load()`'s Notes](../api/basic_json_document/load.md#notes) for exactly what each level does and does not guarantee.

??? example "Example: cache a parsed configuration as an image"

    ```cpp
    --8<-- "examples/basic_json_document__save.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_document__save.output"
    ```

!!! warning "Experimental"

    The image format is versioned but not yet stable, and may change in an incompatible way before it is declared
    stable. It is little-endian only, and tied to the library build that wrote it -- use it to cache a document or to
    hand one to another process running the *same* build, not as a long-term storage format; keep the original JSON
    text if a saved document needs to be readable by a future library version.

The idea of a document you can read without parsing comes from zero-copy formats such as
[FlatBuffers](https://github.com/google/flatbuffers) and [YaFF](https://github.com/yandex/yaff); the check
[`load()`](../api/basic_json_document/load.md) runs follows the idea of FlatBuffers' Verifier. No code is taken from
either.

## Choosing between `json`, `ordered_json`, the SAX interface, and `json_view`

| | [`json`](../api/json.md) / [`ordered_json`](../api/ordered_json.md) | [SAX interface](parsing/sax_interface.md) | [`json_document`](../api/json_document.md) / [`json_view`](../api/json_view.md) | [`json_editable_document`](../api/json_editable_document.md) / [`json_editable_view`](../api/json_editable_view.md) |
|---|---|---|---|---|
| **Ownership** | owns every value | owns nothing; you decide what to keep, in your handler | borrows or owns the *text*; the index is always owned by the document | same as `json_document`; edits go to storage the document owns |
| **Mutability** | freely mutable | not applicable (a one-shot event stream) | read-only | [`set`](../api/basic_json_document/set.md)/[`push_back`](../api/basic_json_document/push_back.md)/[`insert`](../api/basic_json_document/insert.md)/[`erase`](../api/basic_json_document/erase.md) edit in place; the source text is never rewritten |
| **What you get** | a full tree you can read, write, and keep as long as you like | a sequence of callbacks; whatever your handler builds from them | a flat index plus, on demand, [`materialize()`](../api/basic_json_view/materialize.md)d `json`/`ordered_json` values for the parts you actually use | the same, plus [`dump()`](../api/basic_json_view/dump.md) of an edited document that keeps the member order and, with [`number_format::source`](../api/basic_json_view/number_format.md), the spelling of every untouched number |
| **Typical use** | general-purpose JSON handling: config, request/response bodies you build or modify, anything you hold onto | validating or projecting a text into your own data structure without ever holding the whole thing as JSON | large or high-volume input where you only need part of it, or need it repeatedly, and can keep the source text (or a copy) alive for as long as the document lives | a document you read, patch a few fields of, and write back -- a configuration file, for instance -- where the rest of it should come back exactly as it was |
| **Caching/reload** | not applicable -- re-parse, or roll your own serialization | not applicable | [`save()`](../api/basic_json_document/save.md)/[`load()`](../api/basic_json_document/load.md): cache the parsed index as an image and reload it without parsing | same, saving the document's current -- possibly edited -- state |

## Version history

- Added in version 3.13.0.
