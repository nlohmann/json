# Zero-copy JSON views

`<nlohmann/json_view.hpp>` adds a read-only, non-owning way to look at a parsed JSON text, as an alternative to building a [`basic_json`](https://json.nlohmann.me/api/basic_json/index.md) tree with [`parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md).

## The problem

[`basic_json::parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md) builds a tree of `basic_json` values: one allocation for every array and object, and every string copied into its own `std::string`. That is the right trade-off when the program goes on to read and write the value freely, but it does more work than necessary when only a small part of a large JSON text is actually needed, or when the same text is parsed over and over (many small messages, for instance) and most of the resulting tree is thrown away almost immediately.

## The idea

[`basic_json_document::parse()`](https://json.nlohmann.me/api/basic_json_document/parse/index.md) parses the same JSON grammar, with the same options, but instead of a tree it builds a flat index of the values it found: one [16-byte entry](https://json.nlohmann.me/home/architecture/#node-index-of-json-views) per value (and one per object key), in document order. Integers are converted while parsing and stored in their entry. Floating-point numbers and strings are referenced in place in the source text: a float is converted when it is read, and only strings that contain escape sequences are decoded, into one shared buffer owned by the document.

[`basic_json_view`](https://json.nlohmann.me/api/basic_json_view/index.md) is a small, trivially copyable handle (two pointers) into that index. It gives you the read-only, type-inspection part of the `basic_json` interface -- [`type()`](https://json.nlohmann.me/api/basic_json_view/type/index.md) and the `is_*()` predicates, [`size()`](https://json.nlohmann.me/api/basic_json_view/size/index.md)/[`empty()`](https://json.nlohmann.me/api/basic_json_view/empty/index.md) -- as well as element access ([`operator[]`](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/index.md), [`at`](https://json.nlohmann.me/api/basic_json_view/at/index.md), [`front`](https://json.nlohmann.me/api/basic_json_view/front/index.md)/[`back`](https://json.nlohmann.me/api/basic_json_view/back/index.md)), lookup ([`find`](https://json.nlohmann.me/api/basic_json_view/find/index.md), [`contains`](https://json.nlohmann.me/api/basic_json_view/contains/index.md), [`count`](https://json.nlohmann.me/api/basic_json_view/count/index.md)), and iteration ([`begin`](https://json.nlohmann.me/api/basic_json_view/begin/index.md)/[`end`](https://json.nlohmann.me/api/basic_json_view/end/index.md), [`items`](https://json.nlohmann.me/api/basic_json_view/items/index.md)) -- without ever allocating a `basic_json` value. When you do need an actual `basic_json` value for a subtree, [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) builds exactly the one [`parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md) would have produced for it.

## How to use it

Include `<nlohmann/json_view.hpp>` in addition to (or instead of) `<nlohmann/json.hpp>`. Parse into a [`json_document`](https://json.nlohmann.me/api/json_document/index.md), inspect its [`root()`](https://json.nlohmann.me/api/basic_json_document/root/index.md), and `materialize()` when you need a real value. `materialize()` works on any view, not just the root, so you can turn just the subtree you need into a value:

Example: parse a document, inspect its root, and materialize it

```
#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

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

## Ownership and lifetime

A document either **borrows** the text it was parsed from, or **owns** its own copy of it; call [`owns_source()`](https://json.nlohmann.me/api/basic_json_document/owns_source/index.md) to find out which happened. [`parse()`](https://json.nlohmann.me/api/basic_json_document/parse/index.md) decides this from the value category and type of its argument (an lvalue `std::string` is borrowed; an rvalue `std::string` is moved in, owned without a copy; a stream is read into an owned buffer; and so on -- see [`parse`'s Notes](https://json.nlohmann.me/api/basic_json_document/parse/#notes) for the full table). [`parse_copy()`](https://json.nlohmann.me/api/basic_json_document/parse_copy/index.md) always owns a copy, regardless of the input.

A borrowed document depends on your buffer

If a document borrows its text, that text **must outlive the document** (and every view taken from it) and must stay **unmodified** for as long as the document exists, since floating-point values and unescaped strings are read from it lazily. Reading or writing through a view after the underlying buffer is gone is undefined behavior, exactly as it would be for a dangling `std::string_view`.

A view is valid only while all of the following hold:

- the document is alive,
- the document has not been re-parsed since the view was taken (with [`read()`](https://json.nlohmann.me/api/basic_json_document/read/index.md) or [`parse()`](https://json.nlohmann.me/api/basic_json_document/parse/index.md) into it),
- the document has not had [`shrink_to_fit()`](https://json.nlohmann.me/api/basic_json_document/shrink_to_fit/index.md) called on it since, and
- if the document borrows its source text, that text is still alive and unmodified.

Moving the `basic_json_document<>` itself is fine and does **not** invalidate its views: the index is a separate heap allocation that keeps its address across the move. Take a fresh view from [`root()`](https://json.nlohmann.me/api/basic_json_document/root/index.md) whenever any of the other conditions above was not met.

A view can dangle, exactly like a `std::string_view`: nothing stops you from using it after its document is gone. This is deliberate. A view is two pointers and trivially copyable; making it safe (a `std::shared_ptr` in the document and a `std::weak_ptr` in each view) would make it larger, add reference counting to every copy, and a `lock()` to every access -- exactly the costs the view exists to avoid. What is caught is the obvious case: because a view dies with its document, [`root()`](https://json.nlohmann.me/api/basic_json_document/root/index.md) is not callable on a temporary document: `auto v = json_document::parse(text).root();` does not compile. Give the document a name first.

Example: borrowed and owned documents, and when views become invalid

```
#include <iostream>
#include <string>
#include <utility>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    std::cout << std::boolalpha;

    // BORROWED: doc only points into `text`; `text` must outlive `doc`
    std::string text = R"({"a": 1})";
    json_document doc = json_document::parse(text);
    std::cout << doc.owns_source() << '\n'; // false

    // a view is valid as long as the document is alive, has not been
    // re-parsed (read()) or shrunk (shrink_to_fit()), and -- if borrowed --
    // the source text is alive
    nlohmann::json_view v = doc.root();
    std::cout << v.is_object() << '\n';

    // re-parsing the SAME document invalidates views taken before the call;
    // `v` above must not be used after this line
    doc.read(R"([1, 2, 3])");
    v = doc.root(); // take a fresh view instead
    std::cout << v.is_array() << '\n';

    // moving the document does not invalidate views: the node index is
    // heap-allocated and does not move with the document object
    json_document moved = std::move(doc);
    std::cout << v.is_array() << '\n';
}
```

Output:

```
false
true
true
true
```

## What is the same as `parse()`

- **Accept/reject.** [`accept()`](https://json.nlohmann.me/api/basic_json_document/accept/index.md) and [`parse()`](https://json.nlohmann.me/api/basic_json_document/parse/index.md) accept and reject exactly the same inputs as [`basic_json::accept()`](https://json.nlohmann.me/api/basic_json/accept/index.md)/[`basic_json::parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md), with the same `ignore_comments` and `ignore_trailing_commas` options.
- **Errors.** A failing parse throws the same exception -- the same id, message, and position -- because on failure the library's own parser is run on the same bytes to produce the diagnostic. Valid input never pays for this, and the replay builds no values: it costs about a lexing pass up to the error. `allow_exceptions == false` skips the replay and gives a [discarded](https://json.nlohmann.me/api/basic_json_document/is_discarded/index.md) document instead of throwing, just as it gives a discarded value for `basic_json::parse()`.
- **Number classification.** An integer literal that does not fit into the 64-bit integer type becomes a floating-point value, exactly as it does for `basic_json::parse()`.
- **Macros.** [`JSON_STRICT_NUL_HANDLING`](https://json.nlohmann.me/api/macros/json_strict_nul_handling/index.md) and [`JSON_NOEXCEPTION`](https://json.nlohmann.me/api/macros/json_noexception/index.md)/[`JSON_THROW_USER`](https://json.nlohmann.me/api/macros/json_throw_user/index.md) behave the same way they do for `<nlohmann/json.hpp>`. These are the macros that change what the parser accepts or how it reports errors. The others either do not apply ([`JSON_DIAGNOSTICS`](https://json.nlohmann.me/api/macros/json_diagnostics/index.md) needs parent pointers in `basic_json` values) or only affect the values `materialize()` produces, through `BasicJsonType`.

## What is different

- **Only 64-bit integers.** `basic_json_document<BasicJsonType>` requires `BasicJsonType::number_integer_t` and `number_unsigned_t` to both be 64 bits wide; this is a compile-time `static_assert`.
- **A 4 GiB input limit.** An input of 4294967280 bytes (4 GiB minus 16 bytes) or more throws [`out_of_range.416`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range416), a limit `basic_json::parse()` does not have. It keeps an index entry at 16 bytes: offsets and counts are 32 bits wide. The limit is 16 bytes below 2^32, because the parser reads in 16-byte steps, and a position one step past the end must still fit.
- **A stream is always read to its end.** There is no partial/streaming read of an `std::istream`: the stream is read to its end into a buffer the document owns, and parsing starts after that.
- **No source positions on `materialize()`.** Even with [`JSON_DIAGNOSTIC_POSITIONS`](https://json.nlohmann.me/api/macros/json_diagnostic_positions/index.md) enabled, [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) does not set them. The index has the start offset of every value, but not the end of arrays, objects, and escaped strings, which the positions also need.
- **Objects iterate in document order.** [`begin()`](https://json.nlohmann.me/api/basic_json_view/begin/index.md)/ [`end()`](https://json.nlohmann.me/api/basic_json_view/end/index.md) and [`items()`](https://json.nlohmann.me/api/basic_json_view/items/index.md) visit an object's members in the order they appear in the source text. `basic_json`'s default `object_t` is a `std::map`, which sorts by key, so iterating a [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md)d value can print members in a different order than iterating the view they came from.
- **Chained access is safe.** [`operator[]`](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/index.md) with a missing key, an index out of range, or an unresolvable JSON pointer returns a [discarded](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md) view, and `operator[]` on a discarded view returns a discarded view without throwing: `v["a"]["b"][0]` can be tested once at the end. Type errors on values that exist (a key on an array, an index on an object) still throw, and [`at`](https://json.nlohmann.me/api/basic_json_view/at/index.md) throws for every missing value.
- **Duplicate keys: lookups find the first member, `parse()` keeps the last.** See [Duplicate keys](#duplicate-keys) below.
- **No [`JSON_DIAGNOSTICS`](https://json.nlohmann.me/api/macros/json_diagnostics/index.md) path.** Exceptions thrown by `basic_json_view`'s own element access and lookup functions never carry the JSON Pointer path `JSON_DIAGNOSTICS` would otherwise add: the view has no `basic_json` value to point at, so the exception is created without one, regardless of how `BasicJsonType` was built.
- **Ordering comparisons are not provided** by `basic_json_view` -- there is no `operator<`. [`operator==`](https://json.nlohmann.me/api/basic_json_view/operator_eq/index.md) and [`operator!=`](https://json.nlohmann.me/api/basic_json_view/operator_ne/index.md) are provided, though: two views, or a view and a `BasicJsonType` value, compare equal exactly when [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) or [`parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md) would produce equal values for them, without ever building a tree to do it. For ordering, too, [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) is the way to get a value you can compare.

## Duplicate keys

A lookup in a view and in the parsed value can give different answers

If an object in the source text repeats a key, [`operator[]`](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/index.md), [`at`](https://json.nlohmann.me/api/basic_json_view/at/index.md), [`find`](https://json.nlohmann.me/api/basic_json_view/find/index.md), [`value`](https://json.nlohmann.me/api/basic_json_view/value/index.md), [`contains`](https://json.nlohmann.me/api/basic_json_view/contains/index.md), and JSON pointer resolution all return the **first** member with that key. `basic_json::parse()` instead keeps the **last** value of a repeated key, so for `{"a":1,"a":2}`, `view["a"]` is `1` while `parse(text)["a"]` is `2`. [`count`](https://json.nlohmann.me/api/basic_json_view/count/index.md) counts every member with the key, so it is `2` here.

[`begin()`](https://json.nlohmann.me/api/basic_json_view/begin/index.md)/[`end()`](https://json.nlohmann.me/api/basic_json_view/end/index.md) and [`items()`](https://json.nlohmann.me/api/basic_json_view/items/index.md) visit *every* occurrence, in document order, and [`size()`](https://json.nlohmann.me/api/basic_json_view/size/index.md) counts all of them, so `view.size()` can be larger than `view.materialize().size()`.

**Why the first?** A lookup can stop as soon as it finds a match. Returning the last member would force every lookup to scan all members of the object, even when the key is found at the very first one: this made lookups in small objects 1.6 to 3.4 times slower. The hash index of the keys of objects with 128 members or more leads to the first member of a key as well. Other zero-copy parsers that index the source text, such as yyjson and simdjson, also return the first member. RFC 8259 only says that names within an object SHOULD be unique and that the behavior of a receiver that sees duplicates is unpredictable, so neither choice is wrong.

**What stays the same as `parse()`?** [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) and [`get<std::map<...>>()`](https://json.nlohmann.me/api/basic_json_view/get/index.md) replay every member in order, so they keep the *last* value exactly like `basic_json::parse()` (at the position of the first occurrence of the key, for an [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md)).

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

## Getting values out without copying

[`get<T>()`](https://json.nlohmann.me/api/basic_json_view/get/index.md) converts many `T` directly from the flat index, without ever building a `basic_json` value for the conversion: `bool`, arithmetic types, `std::nullptr_t`, `std::string`/other `std::basic_string`s (copied once), `basic_json`/`ordered_json` (via [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md)), `basic_json_view` itself, `std::vector<U>`, and `std::map`/`std::unordered_map` with string-like keys. Every other type -- `std::list`, `std::pair`, `std::array`, enumerations, user types with a `from_json()` -- goes through [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md)`.get<T>()` instead: the subtree is built into a real `basic_json` value first, exactly as [`parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md) would, and converted from there.

Two conversions never copy at all:

- [`get_string()`](https://json.nlohmann.me/api/basic_json_view/get_string/index.md) (equivalently, `get<string_view_t>()`) returns a string as a `string_view_t` pointing into the document's [`source()`](https://json.nlohmann.me/api/basic_json_document/source/index.md) text -- or, for a string that contains escape sequences, into the document's own buffer of decoded strings -- instead of allocating a new `std::string`.
- [`number_token()`](https://json.nlohmann.me/api/basic_json_view/number_token/index.md) returns a number exactly as it was written in the source, e.g. `"1.50"`, `"1E2"`, or an integer with more digits than any number type holds, instead of rounding it into a `double`/`int64_t` the way `get<T>()` (and [`basic_json::parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md)) would.

Both results are only valid as long as the view -- and, for a string with no escapes, the borrowed source text -- is.

## Writing a view back

[`dump()`](https://json.nlohmann.me/api/basic_json_view/dump/index.md) serializes a view directly from the flat index, without ever building a `basic_json` value. An object's members are written in document order, not sorted by key, and *every* occurrence of a repeated key is written, not only the last one -- the same two ways [iteration](#what-is-different) already differs from a [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md)d value, see [Duplicate keys](#duplicate-keys). `materialize().dump()` gives a different result in both respects for a `json_view`.

By default, numbers are written the way [`basic_json::dump()`](https://json.nlohmann.me/api/basic_json/dump/index.md) would. [`number_format::source`](https://json.nlohmann.me/api/basic_json_view/number_format/index.md) instead copies every number exactly as it was written in the source text -- a price like `19.90`, a long order or account ID with more digits than any number type holds, or a high-precision coordinate -- something `basic_json` cannot do at all, since parsing already reduces a number to its parsed `double`/`int64_t` value.

[`operator<<`](https://json.nlohmann.me/api/basic_json_view/operator_ltlt/index.md) writes a view to a stream the way `basic_json`'s does, using the stream's `width`/`fill` for indentation.

## Editing a document

Everything above is read-only: a `json_document`/`json_view` lets you look at a parsed text without copying it, but not change it. [`basic_json_document<BasicJsonType, true>`](https://json.nlohmann.me/api/basic_json_document/index.md) -- more conveniently spelled [`json_editable_document`](https://json.nlohmann.me/api/json_editable_document/index.md) or [`ordered_json_editable_document`](https://json.nlohmann.me/api/ordered_json_editable_document/index.md) -- also lets you [`set`](https://json.nlohmann.me/api/basic_json_document/set/index.md) a value, [`push_back`](https://json.nlohmann.me/api/basic_json_document/push_back/index.md) onto or [`insert`](https://json.nlohmann.me/api/basic_json_document/insert/index.md) into an array, and [`erase`](https://json.nlohmann.me/api/basic_json_document/erase/index.md) an object member or an array element, still without ever building a `basic_json` tree for parts you do not touch.

`Editable` defaults to `false`, so `json_document`/`ordered_json_document` are unaffected -- they carry none of the bookkeeping edits need, and calling `set`/`push_back`/`insert`/`erase` on one is a compile error, not a runtime one.

### Why: editing without reformatting

The `19.90` price from [above](#writing-a-view-back) is exactly the kind of value that makes editing a `json` or `ordered_json` value in place lossy. Say you parse a configuration file, patch one field, and write it back:

- **`json`** re-sorts every key on the way in (`object_t` is a `std::map`) and rewrites every number to its shortest round-trip form on the way out -- a one-field patch turns into a diff that reorders the whole file and rewrites `19.90` to `19.9`.
- **`ordered_json`** keeps the key order, but still rewrites every number the same way: parsing has already reduced it to a `double`/`int64_t`, and there is no way back to how it was spelled in the source text.

An editable document keeps both. [`dump()`](https://json.nlohmann.me/api/basic_json_view/dump/index.md) of an edited document writes members in document order -- a member [`set`](https://json.nlohmann.me/api/basic_json_document/set/index.md) added goes at the end, exactly where it was inserted, and an [`erase`](https://json.nlohmann.me/api/basic_json_document/erase/index.md)d member simply leaves a gap: everything around it keeps its place -- and [`number_format::source`](https://json.nlohmann.me/api/basic_json_view/number_format/index.md) keeps the exact spelling of every number an edit did not itself touch; a number an edit *did* touch is written the way [`BasicJsonType::dump()`](https://json.nlohmann.me/api/basic_json/dump/index.md) would write it, since there is no source spelling for a brand new value.

Example: patch a configuration, keeping member order and number spellings

```
#include <iostream>
#include <nlohmann/json_view.hpp>

using json = nlohmann::json;
using json_editable_document = nlohmann::json_editable_document;
using json_editable_view = nlohmann::json_editable_view;

int main()
{
    // a configuration file, as it might be read from disk
    const std::string text = R"({"name": "cache", "host": "db1", "port": 6379, "price": 19.90})";
    std::cout << text << "\n\n";

    // patch two fields -- "price" is never touched
    json_editable_document doc = json_editable_document::parse(text);
    doc.set(doc.root(), "host", "db2");
    doc.set(doc.root(), "retries", 3);

    // member order (the new member at the end) and the untouched number's
    // exact spelling survive
    std::cout << doc.root().dump(-1, ' ', false, json_editable_view::number_format::source) << '\n';

    // the same patch on a plain json value: keys are sorted (object_t is a
    // std::map), and "price" is rewritten even though the patch never
    // touched it
    json plain = json::parse(text);
    plain["host"] = "db2";
    plain["retries"] = 3;
    std::cout << plain.dump() << '\n';
}
```

Output:

```
{"name": "cache", "host": "db1", "port": 6379, "price": 19.90}

{"name":"cache","host":"db2","port":6379,"price":19.90,"retries":3}
{"host":"db2","name":"cache","port":6379,"price":19.9,"retries":3}
```

### What stays valid, and what an edit costs

The source text itself is **never written**, and the parsed index never moves -- a value keeps the node it was parsed into for as long as it is not itself replaced. So every [view](https://json.nlohmann.me/api/basic_json_view/index.md) taken before an edit, including a previously obtained [`root()`](https://json.nlohmann.me/api/basic_json_document/root/index.md), stays valid and, if it still refers to the edited value, sees the edit; a view of a value a later edit drops or replaces just keeps showing what it last held. New values go to storage the document allocates and owns on demand. The one thing an edit does invalidate is the **iterators** taken over an edited array or object: the first time one of its elements is set, appended to, inserted into, or erased, its elements move from the parsed, fixed layout to a growable block of links so that [`push_back`](https://json.nlohmann.me/api/basic_json_document/push_back/index.md) can later grow it in amortized constant time -- existing elements are not touched, but an iterator that was walking the old layout no longer matches. A string obtained with [`get_string()`](https://json.nlohmann.me/api/basic_json_view/get_string/index.md) is unaffected either way and stays valid across further edits. See [`basic_json_document`'s Edits](https://json.nlohmann.me/api/basic_json_document/#edits) for the details, and [`set`'s Exception safety](https://json.nlohmann.me/api/basic_json_document/set/#exception-safety) for what an edit guarantees if it throws (the *basic* guarantee, not the strong one `dump()` and the read-only functions provide). How edits are kept in the index is described in the [architecture overview](https://json.nlohmann.me/home/architecture/#node-index-of-json-views).

## Images

[`save()`](https://json.nlohmann.me/api/basic_json_document/save/index.md) writes a document as an *image*: a byte buffer that [`load()`](https://json.nlohmann.me/api/basic_json_document/load/index.md) reads back into a document without parsing -- no lexing, no building the node index, nothing but copying the nodes and pointing the text and the decoded strings at the image. Where [`parse_copy()`](https://json.nlohmann.me/api/basic_json_document/parse_copy/index.md) still has to scan the whole input, [`load()`](https://json.nlohmann.me/api/basic_json_document/load/index.md) turns that scan into a copy of the node index alone.

**Why.** A document that is parsed once and then read many times -- a configuration loaded at startup, a template rendered on every request, a large reference dataset a worker process needs in memory -- pays for parsing once but can amortize [`save()`](https://json.nlohmann.me/api/basic_json_document/save/index.md)'s cost across every later load. That makes images useful for a cache: save a document the first time it is parsed (to a file, a shared-memory segment, an in-process cache), and [`load()`](https://json.nlohmann.me/api/basic_json_document/load/index.md) it on every later use instead of parsing the source text again. They are just as useful for handing a parsed document to another process (or a forked worker) running the same build of the library, since [`load()`](https://json.nlohmann.me/api/basic_json_document/load/index.md) turns the transfer into a copy of the node index plus pointers into the received bytes, not a re-parse.

**Choosing a check.** [`load()`](https://json.nlohmann.me/api/basic_json_document/load/index.md) takes an [`image_check`](https://json.nlohmann.me/api/basic_json_document/load/#image_check) that trades validation against speed: `image_check::full` (the default) checks everything the parser itself guarantees, so a checked image is exactly as safe to read and serialize as a freshly parsed document -- the right choice whenever the image did not come straight from this process's own [`save()`](https://json.nlohmann.me/api/basic_json_document/save/index.md), such as a file or a network peer. `image_check::bounds` only checks structure and bounds -- cheaper, since it skips scanning the text and the decoded strings -- and fits a cache the process trusts, one it wrote and reads back itself. `image_check::none` skips validation entirely, for an image trusted as much as the process's own memory. See [`load()`'s Notes](https://json.nlohmann.me/api/basic_json_document/load/#notes) for exactly what each level does and does not guarantee.

Example: cache a parsed configuration as an image

```
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    std::cout << std::boolalpha;

    // a configuration a service parses once and then caches as an image, so
    // that later requests can load() it instead of parsing the text again
    const std::string text = R"({"name": "cache", "host": "db1", "port": 6379, "replicas": ["db2", "db3"]})";
    const json_document config = json_document::parse(text);

    // save() turns the parsed document into a byte buffer: a 64-byte header,
    // the node index, the source text, and the decoded strings
    const std::vector<std::uint8_t> image = config.save();
    std::cout << image.size() << '\n';

    // the same document always saves to the same bytes
    std::cout << (image == json_document::parse(text).save()) << '\n';

    // loading the image back needs no parsing, yet dumps exactly what
    // parsing the text produced
    const json_document reloaded = json_document::load(image);
    std::cout << (reloaded.root().dump() == config.root().dump()) << '\n';
}
```

Output:

```
316
true
true
```

Experimental

The image format is versioned but not yet stable, and may change in an incompatible way before it is declared stable. It is little-endian only, and tied to the library build that wrote it -- use it to cache a document or to hand one to another process running the *same* build, not as a long-term storage format; keep the original JSON text if a saved document needs to be readable by a future library version.

The idea of a document you can read without parsing comes from zero-copy formats such as [FlatBuffers](https://github.com/google/flatbuffers) and [YaFF](https://github.com/yandex/yaff); the check [`load()`](https://json.nlohmann.me/api/basic_json_document/load/index.md) runs follows the idea of FlatBuffers' Verifier. No code is taken from either.

## Choosing between `json`, `ordered_json`, the SAX interface, and `json_view`

|                    | [`json`](https://json.nlohmann.me/api/json/index.md) / [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md) | [SAX interface](https://json.nlohmann.me/features/parsing/sax_interface/index.md)                         | [`json_document`](https://json.nlohmann.me/api/json_document/index.md) / [`json_view`](https://json.nlohmann.me/api/json_view/index.md)                                                                                 | [`json_editable_document`](https://json.nlohmann.me/api/json_editable_document/index.md) / [`json_editable_view`](https://json.nlohmann.me/api/json_editable_view/index.md)                                                                                                                                                                                         |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Ownership**      | owns every value                                                                                                            | owns nothing; you decide what to keep, in your handler                                                    | borrows or owns the *text*; the index is always owned by the document                                                                                                                                                   | same as `json_document`; edits go to storage the document owns                                                                                                                                                                                                                                                                                                      |
| **Mutability**     | freely mutable                                                                                                              | not applicable (a one-shot event stream)                                                                  | read-only                                                                                                                                                                                                               | [`set`](https://json.nlohmann.me/api/basic_json_document/set/index.md)/[`push_back`](https://json.nlohmann.me/api/basic_json_document/push_back/index.md)/[`insert`](https://json.nlohmann.me/api/basic_json_document/insert/index.md)/[`erase`](https://json.nlohmann.me/api/basic_json_document/erase/index.md) edit in place; the source text is never rewritten |
| **What you get**   | a full tree you can read, write, and keep as long as you like                                                               | a sequence of callbacks; whatever your handler builds from them                                           | a flat index plus, on demand, [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md)d `json`/`ordered_json` values for the parts you actually use                                         | the same, plus [`dump()`](https://json.nlohmann.me/api/basic_json_view/dump/index.md) of an edited document that keeps the member order and, with [`number_format::source`](https://json.nlohmann.me/api/basic_json_view/number_format/index.md), the spelling of every untouched number                                                                            |
| **Typical use**    | general-purpose JSON handling: config, request/response bodies you build or modify, anything you hold onto                  | validating or projecting a text into your own data structure without ever holding the whole thing as JSON | large or high-volume input where you only need part of it, or need it repeatedly, and can keep the source text (or a copy) alive for as long as the document lives                                                      | a document you read, patch a few fields of, and write back -- a configuration file, for instance -- where the rest of it should come back exactly as it was                                                                                                                                                                                                         |
| **Caching/reload** | not applicable -- re-parse, or roll your own serialization                                                                  | not applicable                                                                                            | [`save()`](https://json.nlohmann.me/api/basic_json_document/save/index.md)/[`load()`](https://json.nlohmann.me/api/basic_json_document/load/index.md): cache the parsed index as an image and reload it without parsing | same, saving the document's current -- possibly edited -- state                                                                                                                                                                                                                                                                                                     |

## Version history

- Added in version 3.13.0 unreleased.
