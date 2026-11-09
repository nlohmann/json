# Differences from `basic_json`

A [`basic_json_view`](https://json.nlohmann.me/api/basic_json_view/index.md) offers the read-only part of the [`basic_json`](https://json.nlohmann.me/api/basic_json/index.md) interface, and in most respects it behaves exactly like the value [`basic_json::parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md) would have built from the same text. This page lists where it does not: what a document parses differently, what a view's functions do differently, and which parts of the `basic_json` interface a view does not have.

## Summary

|                                                           | `basic_json` value from `parse()`                          | view of a `json_document`                                                                         | to get the `basic_json` behavior |
| --------------------------------------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | -------------------------------- |
| [Integer types](#parsing)                                 | any `number_integer_t`/`number_unsigned_t`                 | 64-bit only (compile-time check)                                                                  | —                                |
| [Input size](#parsing)                                    | unlimited                                                  | less than 4 GiB                                                                                   | —                                |
| [Parser callbacks](#parsing)                              | `parser_callback_t`                                        | none                                                                                              | filter while iterating           |
| [`operator[]` on a missing key or index](#element-access) | inserts (non-`const`) or undefined behavior (`const`)      | returns a discarded view                                                                          | —                                |
| [Object member order](#object-member-order)               | sorted by key (`json`), insertion order (`ordered_json`)   | document order                                                                                    | `materialize()`                  |
| [Repeated keys](#duplicate-keys)                          | the last value is kept                                     | lookups find the first member; iteration, `size()`, and `dump()` see all of them                  | `materialize()`                  |
| [Conversions](#conversions)                               | `get<T>()`, implicit conversions, `get_ptr()`, `get_ref()` | `get<T>()`, `get_string()`, `number_token()`                                                      | `materialize()`                  |
| [Number spelling](#serialization)                         | lost when parsing                                          | kept: `number_token()`, `number_format::source`                                                   | —                                |
| [Comparison](#comparison)                                 | `==`, `!=`, `<`, `<=>`, ...                                | `==` and `!=` only                                                                                | `materialize()`                  |
| [Modification](#what-a-view-does-not-have)                | member functions of the value                              | only through an [editable document](https://json.nlohmann.me/features/json_view/editing/index.md) | `materialize()`                  |
| [Iterators](#what-a-view-does-not-have)                   | bidirectional (`rbegin()`/`rend()`)                        | forward only                                                                                      | `materialize()`                  |

Each row is one difference; the last column names the way to get `basic_json`'s behavior from a view, where there is one.

## Parsing

### What is the same

- **Accept/reject.** [`accept()`](https://json.nlohmann.me/api/basic_json_document/accept/index.md) and [`parse()`](https://json.nlohmann.me/api/basic_json_document/parse/index.md) accept and reject exactly the same inputs as [`basic_json::accept()`](https://json.nlohmann.me/api/basic_json/accept/index.md)/[`basic_json::parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md), with the same `ignore_comments` and `ignore_trailing_commas` options.
- **Errors.** A failing parse throws the same exception — the same id, message, and position — because on failure the library's own parser is run on the same bytes to produce the diagnostic. Valid input never pays for this, and the replay builds no values: it costs about a lexing pass up to the error. `allow_exceptions == false` skips the replay and gives a [discarded](https://json.nlohmann.me/api/basic_json_document/is_discarded/index.md) document instead of throwing, just as it gives a discarded value for `basic_json::parse()`.
- **Number classification.** An integer literal that does not fit into the 64-bit integer type becomes a floating-point value, exactly as it does for `basic_json::parse()`.
- **Macros.** [`JSON_STRICT_NUL_HANDLING`](https://json.nlohmann.me/api/macros/json_strict_nul_handling/index.md) and [`JSON_NOEXCEPTION`](https://json.nlohmann.me/api/macros/json_noexception/index.md)/[`JSON_THROW_USER`](https://json.nlohmann.me/api/macros/json_throw_user/index.md) behave the same way they do for `<nlohmann/json.hpp>`. These are the macros that change what the parser accepts or how it reports errors. The other macros only affect the values `materialize()` produces, through `BasicJsonType`. Two of them also add context to the exceptions of views, see [Exception context](#exception-context).

### What is different

- **Only 64-bit integers.** `basic_json_document<BasicJsonType>` requires `BasicJsonType::number_integer_t` and `number_unsigned_t` to both be 64 bits wide; this is a compile-time `static_assert`.
- **A 4 GiB input limit.** An input of 4294967280 bytes (4 GiB minus 16 bytes) or more throws [`out_of_range.416`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range416), a limit `basic_json::parse()` does not have. It keeps an index entry at 16 bytes: offsets and counts are 32 bits wide. The limit is 16 bytes below 2^32, because the parser reads in 16-byte steps, and a position one step past the end must still fit.
- **A stream is always read to its end.** There is no partial/streaming read of an `std::istream`: the stream is read to its end into a buffer the document owns, and parsing starts after that. For a file, reading it into a `std::string` yourself and parsing that (an lvalue is borrowed) is therefore not more expensive in memory, and was about 6 to 12 % faster than parsing from an `std::ifstream`.
- **No parser callbacks.** [`parse()`](https://json.nlohmann.me/api/basic_json_document/parse/index.md) takes no [`parser_callback_t`](https://json.nlohmann.me/api/basic_json/parser_callback_t/index.md): a document always indexes the whole text. Skip the values you do not need when reading the view instead.
- **JSON text only.** A document is parsed from JSON text; there is no counterpart of [`from_cbor()`](https://json.nlohmann.me/api/basic_json/from_cbor/index.md) and the other binary formats, and [`is_binary()`](https://json.nlohmann.me/api/basic_json_view/is_binary/index.md) is always `false`.

## Element access

**Chained access is safe.** [`operator[]`](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/index.md) with a missing key, an index out of range, or an unresolvable JSON pointer returns a [discarded](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md) view, and `operator[]` on a discarded view returns a discarded view without throwing: `v["a"]["b"][0]` can be tested once at the end. Type errors on values that exist (a key on an array, an index on an object) still throw, and [`at`](https://json.nlohmann.me/api/basic_json_view/at/index.md) throws for every missing value.

`basic_json`'s non-`const` `operator[]` instead inserts a missing key, and its `const` `operator[]` has undefined behavior for one.

## Objects

### Object member order

[`begin()`](https://json.nlohmann.me/api/basic_json_view/begin/index.md)/[`end()`](https://json.nlohmann.me/api/basic_json_view/end/index.md) and [`items()`](https://json.nlohmann.me/api/basic_json_view/items/index.md) visit an object's members in the order they appear in the source text. `basic_json`'s default `object_t` is a `std::map`, which sorts by key, so iterating a [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md)d value can print members in a different order than iterating the view they came from. [`dump()`](https://json.nlohmann.me/api/basic_json_view/dump/index.md) of a view writes members in document order as well.

### Duplicate keys

A lookup in a view and in the parsed value can give different answers

If an object in the source text repeats a key, [`operator[]`](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/index.md), [`at`](https://json.nlohmann.me/api/basic_json_view/at/index.md), [`find`](https://json.nlohmann.me/api/basic_json_view/find/index.md), [`value`](https://json.nlohmann.me/api/basic_json_view/value/index.md), [`contains`](https://json.nlohmann.me/api/basic_json_view/contains/index.md), and JSON pointer resolution all return the **first** member with that key. `basic_json::parse()` instead keeps the **last** value of a repeated key, so for `{"a":1,"a":2}`, `view["a"]` is `1` while `parse(text)["a"]` is `2`. [`count`](https://json.nlohmann.me/api/basic_json_view/count/index.md) counts every member with the key, so it is `2` here.

[`begin()`](https://json.nlohmann.me/api/basic_json_view/begin/index.md)/[`end()`](https://json.nlohmann.me/api/basic_json_view/end/index.md) and [`items()`](https://json.nlohmann.me/api/basic_json_view/items/index.md) visit *every* occurrence, in document order, and [`size()`](https://json.nlohmann.me/api/basic_json_view/size/index.md) counts all of them, so `view.size()` can be larger than `view.materialize().size()`. [`dump()`](https://json.nlohmann.me/api/basic_json_view/dump/index.md) writes every occurrence, too, so `materialize().dump()` gives a different result for such an object.

**Why the first?** A lookup can stop as soon as it finds a match. Returning the last member would force every lookup to scan all members of the object, even when the key is found at the very first one: this made lookups in small objects 1.6 to 3.4 times slower. The hash index of the keys of objects with 128 members or more leads to the first member of a key as well. Other zero-copy parsers that index the source text, such as yyjson and simdjson, also return the first member. RFC 8259 only says that names within an object SHOULD be unique and that the behavior of a receiver that sees duplicates is unpredictable, so neither choice is wrong.

The same holds for [`get<T>()`](https://json.nlohmann.me/api/basic_json_view/get/index.md) of a type whose `from_json()` reads the view, such as the types of the `NLOHMANN_DEFINE_TYPE_*` macros: their members are looked up, so `get<point>()` of `{"x":1,"x":2}` reads `x == 1`, while `materialize().get<point>()` reads `2`.

**What stays the same as `parse()`?** [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) and [`get<std::map<...>>()`](https://json.nlohmann.me/api/basic_json_view/get/index.md) (and the other containers built from an object) replay every member in order, so they keep the *last* value exactly like `basic_json::parse()` (at the position of the first occurrence of the key, for an [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md)).

**How do I get the value `parse()` would give?** Either call `view.materialize()` and look the key up in the result, or iterate the members and keep the last match:

```
// the last member with the key "a", as parse() would keep it
json_view last;
for (const auto item : view.items())
{
    if (item.key() == "a")
    {
        last = item.value();
    }
}
```

If you cannot trust the source text to have unique keys, check [`size()`](https://json.nlohmann.me/api/basic_json_view/size/index.md) against the number of distinct keys, or reject duplicates when iterating.

## Conversions

- **No implicit conversions.** A view has no `operator ValueType()`, no `get_ptr()`, and no `get_ref()`; use [`get<T>()`](https://json.nlohmann.me/api/basic_json_view/get/index.md), or [`get_string()`](https://json.nlohmann.me/api/basic_json_view/get_string/index.md) for a string without a copy.
- **`from_json()` overloads.** [`get<T>()`](https://json.nlohmann.me/api/basic_json_view/get/index.md) calls `T`'s `from_json()` with the view only if that `from_json()` accepts views, and with [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) otherwise; see [A `from_json()` that reads views](https://json.nlohmann.me/features/json_view/generic_code/#a-from_json-that-reads-views). Both give the same result except for [repeated keys](#duplicate-keys).
- **`string_view` members.** A struct with a `std::string_view` member decoded from a view points into the document, see [`string_view` members](https://json.nlohmann.me/features/json_view/reading/#string_view-members). Decoding the same struct from a `json` value compiles, too, but dangles at once if the value is a temporary.

## Serialization

[`dump()`](https://json.nlohmann.me/api/basic_json_view/dump/index.md) writes numbers the way [`basic_json::dump()`](https://json.nlohmann.me/api/basic_json/dump/index.md) would by default, but writes object members in [document order](#object-member-order) and writes [every occurrence of a repeated key](#duplicate-keys).

A view can also do what a `basic_json` value cannot: [`number_token()`](https://json.nlohmann.me/api/basic_json_view/number_token/index.md) and [`number_format::source`](https://json.nlohmann.me/api/basic_json_view/number_format/index.md) give every number exactly as it was spelled in the source text, while parsing into `basic_json` already reduces a number to its `double`/`int64_t` value. See [Writing a view back](https://json.nlohmann.me/features/json_view/reading/#writing-a-view-back).

## Comparison

**Ordering comparisons are not provided** by `basic_json_view` — there is no `operator<`. [`operator==`](https://json.nlohmann.me/api/basic_json_view/operator_eq/index.md) and [`operator!=`](https://json.nlohmann.me/api/basic_json_view/operator_ne/index.md) are provided, though: two views, or a view and a `BasicJsonType` value, compare equal exactly when [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) or [`parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md) would produce equal values for them, without ever building a tree to do it. For ordering, [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) is the way to get a value you can compare.

## Exception context

With [`JSON_DIAGNOSTICS`](https://json.nlohmann.me/api/macros/json_diagnostics/index.md), an exception of a view names the JSON Pointer path of the value within the document, and with [`JSON_DIAGNOSTIC_POSITIONS`](https://json.nlohmann.me/api/macros/json_diagnostic_positions/index.md), it names the bytes of the value in the source text, as they do for the exceptions of `basic_json`.

A view has neither parent pointers nor stored positions, so both are found from the document's index when the exception is thrown. This takes time linear in the size of the document. One exception has neither: `key()` of an iterator over an array or a primitive value ([`invalid_iterator.207`](https://json.nlohmann.me/home/exceptions/#jsonexceptioninvalid_iterator207)), because a view's iterator does not know the value it iterates over.

**Fewer source positions after edits.** With [`JSON_DIAGNOSTIC_POSITIONS`](https://json.nlohmann.me/api/macros/json_diagnostic_positions/index.md) enabled, [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) sets the same positions as `basic_json::parse()`. In an [editable document](https://json.nlohmann.me/features/json_view/editing/index.md), a value written by an edit has none, and neither has an array or object whose elements changed or whose last element has none; a `basic_json` value keeps its positions when it is changed. See [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/#notes).

## What a view does not have

A view is a read-only handle. These parts of the `basic_json` interface have no counterpart on a view; [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) the subtree to use them:

- **Modifiers** such as `push_back`, `insert`, `erase`, `update`, or `operator=`. A view never changes a value itself; an [editable document](https://json.nlohmann.me/features/json_view/editing/index.md) changes the values its views refer to through [`set`](https://json.nlohmann.me/api/basic_json_document/set/index.md), [`push_back`](https://json.nlohmann.me/api/basic_json_document/push_back/index.md), [`insert`](https://json.nlohmann.me/api/basic_json_document/insert/index.md), and [`erase`](https://json.nlohmann.me/api/basic_json_document/erase/index.md).
- **Reverse iteration.** A view's iterator is a forward iterator; there is no `rbegin()`/`rend()`.
- **JSON Patch and friends**: [`patch()`](https://json.nlohmann.me/api/basic_json/patch/index.md), [`merge_patch()`](https://json.nlohmann.me/api/basic_json/merge_patch/index.md), [`diff()`](https://json.nlohmann.me/api/basic_json/diff/index.md), [`flatten()`](https://json.nlohmann.me/api/basic_json/flatten/index.md).
- **Binary formats**: [`to_cbor()`](https://json.nlohmann.me/api/basic_json/to_cbor/index.md) and the other writers, and binary values ([`get_binary()`](https://json.nlohmann.me/api/basic_json/get_binary/index.md)).

## See also

- [Zero-copy JSON views](https://json.nlohmann.me/features/json_view/index.md) - overview
- [`basic_json_view`](https://json.nlohmann.me/api/basic_json_view/index.md) - the full interface of a view
- [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) - build the `basic_json` value of a view

## Version history

- Added in version 3.13.0 unreleased.
