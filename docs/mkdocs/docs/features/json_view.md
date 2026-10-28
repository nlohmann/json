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
order. Integers are converted while parsing and stored in their entry. Floating-point numbers and strings are
referenced in place in the source text: a float is converted when it is read, and only strings that contain escape
sequences are decoded, into one shared buffer owned by the document.

[`basic_json_view`](../api/basic_json_view/index.md) is a small, trivially copyable handle (two pointers) into that
index. It gives you the read-only, type-inspection part of the `basic_json` interface —
[`type()`](../api/basic_json_view/type.md) and the `is_*()` predicates,
[`size()`](../api/basic_json_view/size.md)/[`empty()`](../api/basic_json_view/empty.md) — as well as element access
([`operator[]`](../api/basic_json_view/operator%5B%5D.md), [`at`](../api/basic_json_view/at.md),
[`front`](../api/basic_json_view/front.md)/[`back`](../api/basic_json_view/back.md)), lookup
([`find`](../api/basic_json_view/find.md), [`contains`](../api/basic_json_view/contains.md),
[`count`](../api/basic_json_view/count.md)), and iteration
([`begin`](../api/basic_json_view/begin.md)/[`end`](../api/basic_json_view/end.md),
[`items`](../api/basic_json_view/items.md)) — without ever allocating a `basic_json` value. When you do need an
actual `basic_json` value for a subtree, [`materialize()`](../api/basic_json_view/materialize.md) builds exactly the
one [`parse()`](../api/basic_json/parse.md) would have produced for it.

The same small text, parsed both ways:

<div class="nj-fig-wrap" markdown>
--8<-- "images/json_view_layout.svg"
</div>

<p class="nj-caption" markdown>Top: the tree of separate heap allocations that `basic_json::parse()` builds. Bottom: `json_document::parse()` keeps the source text and builds one flat index of 16-byte nodes that point back into it, plus a buffer of decoded strings.</p>

## How to use it

Include `<nlohmann/json_view.hpp>` in addition to (or instead of) `<nlohmann/json.hpp>`. Parse into a
[`json_document`](../api/json_document.md), inspect its [`root()`](../api/basic_json_document/root.md), and
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

[`ordered_json_document`](../api/ordered_json_document.md) is the equivalent for
[`ordered_json`](../api/ordered_json.md), just as [`ordered_json`](../api/ordered_json.md) is to
[`json`](../api/json.md).

## Ownership and lifetime

A document either **borrows** the text it was parsed from, or **owns** its own copy of it; call
[`owns_source()`](../api/basic_json_document/owns_source.md) to find out which happened.
[`parse()`](../api/basic_json_document/parse.md) decides this from the value category and type of its argument (an
lvalue `#!cpp std::string` is borrowed; an rvalue `#!cpp std::string` is moved in, owned without a copy; a stream is
read into an owned buffer; and so on — see [`parse`'s Notes](../api/basic_json_document/parse.md#notes) for the full
table). [`parse_copy()`](../api/basic_json_document/parse_copy.md) always owns a copy, regardless of the input.

!!! warning "A borrowed document depends on your buffer"

    If a document borrows its text, that text **must outlive the document** (and every view taken from it) and must
    stay **unmodified** for as long as the document exists, since floating-point values and unescaped strings are
    read from it lazily. Reading or writing through a view after the underlying buffer is gone is undefined behavior,
    exactly as it would be for a dangling `#!cpp std::string_view`.

A view is valid only while all of the following hold:

- the document is alive,
- the document has not been re-parsed since the view was taken (with [`read()`](../api/basic_json_document/read.md)
  or [`parse()`](../api/basic_json_document/parse.md) into it),
- the document has not had [`shrink_to_fit()`](../api/basic_json_document/shrink_to_fit.md) called on it since, and
- if the document borrows its source text, that text is still alive and unmodified.

Moving the `basic_json_document<>` itself is fine and does **not** invalidate its views: the index is a separate heap
allocation that keeps its address across the move. Take a fresh view from [`root()`](../api/basic_json_document/root.md)
whenever any of the other conditions above was not met.

<div class="nj-fig-wrap" markdown>
--8<-- "images/json_view_lifetime.svg"
</div>

<p class="nj-caption" markdown>Four timelines of a document and its views, each bar showing when an object is alive or valid and when it dangles. Destroying the borrowed text, re-parsing, or shrinking the document invalidates the views taken before; moving the document does not.</p>

A view can dangle, exactly like a `#!cpp std::string_view`: nothing stops you from using it after its document is
gone. This is deliberate. A view is two pointers and trivially copyable; making it safe (a `#!cpp std::shared_ptr` in
the document and a `#!cpp std::weak_ptr` in each view) would make it larger, add reference counting to every copy,
and a `lock()` to every access — exactly the costs the view exists to avoid. What is caught is the obvious case:
because a view dies with its document, [`root()`](../api/basic_json_document/root.md) is not callable on a temporary
document: `#!cpp auto v = json_document::parse(text).root();` does not compile. Give the document a name first.

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
- **Errors.** A failing parse throws the same exception — the same id, message, and position — because on failure
  the library's own parser is run on the same bytes to produce the diagnostic. Valid input never pays for this, and
  the replay builds no values: it costs about a lexing pass up to the error.
  `#!cpp allow_exceptions == false` skips the replay and gives a
  [discarded](../api/basic_json_document/is_discarded.md) document instead of throwing, just as it gives a discarded
  value for `#!cpp basic_json::parse()`.
- **Number classification.** An integer literal that does not fit into the 64-bit integer type becomes a
  floating-point value, exactly as it does for `#!cpp basic_json::parse()`.
- **Macros.** [`JSON_STRICT_NUL_HANDLING`](../api/macros/json_strict_nul_handling.md) and
  [`JSON_NOEXCEPTION`](../api/macros/json_noexception.md)/[`JSON_THROW_USER`](../api/macros/json_throw_user.md)
  behave the same way they do for `<nlohmann/json.hpp>`. These are the macros that change what the parser accepts or
  how it reports errors. The others either do not apply ([`JSON_DIAGNOSTICS`](../api/macros/json_diagnostics.md)
  needs parent pointers in `basic_json` values) or only affect the values `materialize()` produces, through
  `BasicJsonType`.

## What is different

- **Only 64-bit integers.** `basic_json_document<BasicJsonType>` requires `BasicJsonType::number_integer_t` and
  `number_unsigned_t` to both be 64 bits wide; this is a compile-time `#!cpp static_assert`.
- **A 4 GiB input limit.** An input of 4294967280 bytes (4 GiB minus 16 bytes) or more throws
  [`out_of_range.416`](../home/exceptions.md#jsonexceptionout_of_range416), a limit
  `#!cpp basic_json::parse()` does not have. It keeps an index entry at 16 bytes: offsets and counts are 32 bits
  wide. The limit is 16 bytes below 2^32, because the parser reads in 16-byte steps, and a position one step past the
  end must still fit.
- **A stream is always read to its end.** There is no partial/streaming read of an `#!cpp std::istream`: the stream
  is read to its end into a buffer the document owns, and parsing starts after that.
- **Fewer source positions after edits.** With
  [`JSON_DIAGNOSTIC_POSITIONS`](../api/macros/json_diagnostic_positions.md) enabled,
  [`materialize()`](../api/basic_json_view/materialize.md) sets the same positions as `#!cpp basic_json::parse()`.
  In an [editable document](../api/json_editable_document.md), a value written by an edit has none, and neither has
  an array or object whose elements changed or whose last element has none; a `basic_json` value keeps its positions
  when it is changed. See [`materialize()`](../api/basic_json_view/materialize.md#notes).
- **Objects iterate in document order.** [`begin()`](../api/basic_json_view/begin.md)/
  [`end()`](../api/basic_json_view/end.md) and [`items()`](../api/basic_json_view/items.md) visit an object's
  members in the order they appear in the source text. `basic_json`'s default `object_t` is a `std::map`, which
  sorts by key, so iterating a [`materialize()`](../api/basic_json_view/materialize.md)d value can print members in
  a different order than iterating the view they came from.
- **Chained access is safe.** [`operator[]`](../api/basic_json_view/operator%5B%5D.md) with a missing key, an index
  out of range, or an unresolvable JSON pointer returns a [discarded](../api/basic_json_view/is_discarded.md) view, and
  `operator[]` on a discarded view returns a discarded view without throwing: `#!cpp v["a"]["b"][0]` can be tested
  once at the end. Type errors on values that exist (a key on an array, an index on an object) still throw, and
  [`at`](../api/basic_json_view/at.md) throws for every missing value.
- **Duplicate keys: lookups find the first member, `parse()` keeps the last.** See [Duplicate keys](#duplicate-keys)
  below.
- **No [`JSON_DIAGNOSTICS`](../api/macros/json_diagnostics.md) path.** Exceptions thrown by `basic_json_view`'s own
  element access and lookup functions never carry the JSON Pointer path `JSON_DIAGNOSTICS` would otherwise add: the
  view has no `basic_json` value to point at, so the exception is created without one, regardless of how
  `BasicJsonType` was built.
- **Ordering comparisons are not provided** by `basic_json_view` — there is no `#!cpp operator<`.
  [`operator==`](../api/basic_json_view/operator_eq.md) and [`operator!=`](../api/basic_json_view/operator_ne.md) are
  provided, though: two views, or a view and a `BasicJsonType` value, compare equal exactly when
  [`materialize()`](../api/basic_json_view/materialize.md) or [`parse()`](../api/basic_json/parse.md) would produce
  equal values for them, without ever building a tree to do it. For ordering, too,
  [`materialize()`](../api/basic_json_view/materialize.md) is the way to get a value you can compare.

## Duplicate keys

!!! warning "A lookup in a view and in the parsed value can give different answers"

    If an object in the source text repeats a key, [`operator[]`](../api/basic_json_view/operator%5B%5D.md),
    [`at`](../api/basic_json_view/at.md), [`find`](../api/basic_json_view/find.md),
    [`value`](../api/basic_json_view/value.md), [`contains`](../api/basic_json_view/contains.md), and JSON pointer
    resolution all return the **first** member with that key. `basic_json::parse()` instead keeps the **last** value
    of a repeated key, so for `#!cpp {"a":1,"a":2}`, `#!cpp view["a"]` is `#!cpp 1` while `#!cpp parse(text)["a"]` is
    `#!cpp 2`. [`count`](../api/basic_json_view/count.md) counts every member with the key, so it is `#!cpp 2` here.

[`begin()`](../api/basic_json_view/begin.md)/[`end()`](../api/basic_json_view/end.md) and
[`items()`](../api/basic_json_view/items.md) visit *every* occurrence, in document order, and
[`size()`](../api/basic_json_view/size.md) counts all of them, so `#!cpp view.size()` can be larger than
`#!cpp view.materialize().size()`.

**Why the first?** A lookup can stop as soon as it finds a match. Returning the last member would force every lookup
to scan all members of the object, even when the key is found at the very first one: this made lookups in small
objects 1.6 to 3.4 times slower. The hash index of the keys of objects with 128 members or more leads to the first member of a
key as well. Other zero-copy parsers that index the source text, such as yyjson and simdjson, also return the first
member. RFC 8259 only says that names within an object SHOULD be unique and that the behavior of a receiver that sees
duplicates is unpredictable, so neither choice is wrong.

The same holds for [`get<T>()`](../api/basic_json_view/get.md) of a type whose `from_json()` reads the view, such as
the types of the `NLOHMANN_DEFINE_TYPE_*` macros: their members are looked up, so `#!cpp get<point>()` of
`#!cpp {"x":1,"x":2}` reads `#!cpp x == 1`, while `#!cpp materialize().get<point>()` reads `#!cpp 2`.

**What stays the same as `parse()`?** [`materialize()`](../api/basic_json_view/materialize.md) and
[`get<std::map<...>>()`](../api/basic_json_view/get.md) replay every member in order, so they keep the *last* value
exactly like `#!cpp basic_json::parse()` (at the position of the first occurrence of the key, for an
[`ordered_json`](../api/ordered_json.md)).

**How do I get the value `parse()` would give?** Either call `#!cpp view.materialize()` and look the key up in the
result, or iterate the members and keep the last match:

```cpp
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

If you cannot trust the source text to have unique keys, check [`size()`](../api/basic_json_view/size.md) against the
number of distinct keys, or reject duplicates when iterating.

## Getting values out without copying

[`get<T>()`](../api/basic_json_view/get.md) converts most `T` directly from the flat index, without ever building a
`basic_json` value for the conversion: `#!cpp bool`, arithmetic types, `#!cpp std::nullptr_t`,
`#!cpp std::string`/other `#!cpp std::basic_string`s (copied once), `basic_json_view` itself, the standard containers
and other types the library converts (`#!cpp std::vector`, `#!cpp std::map`, `#!cpp std::list`, `#!cpp std::array`,
`#!cpp std::pair`, `#!cpp std::tuple`, `#!cpp std::optional`, ...), and the types of the `NLOHMANN_DEFINE_TYPE_*` and
`NLOHMANN_JSON_SERIALIZE_ENUM` macros. Types whose `from_json()` is written for `basic_json` only go through
[`materialize()`](../api/basic_json_view/materialize.md)`.get<T>()` instead: the subtree is built into a real
`basic_json` value first, exactly as [`parse()`](../api/basic_json/parse.md) would, and converted from there. See
[Writing generic code](#writing-generic-code) for how to write a `from_json()` that reads views.

Two conversions never copy at all:

- [`get_string()`](../api/basic_json_view/get_string.md) (equivalently, `#!cpp get<string_view_t>()`) returns a
  string as a `string_view_t` pointing into the document's [`source()`](../api/basic_json_document/source.md) text —
  or, for a string that contains escape sequences, into the document's own buffer of decoded strings — instead of
  allocating a new `#!cpp std::string`.
- [`number_token()`](../api/basic_json_view/number_token.md) returns a number exactly as it was written in the
  source, e.g. `#!cpp "1.50"`, `#!cpp "1E2"`, or an integer with more digits than any number type holds, instead of
  rounding it into a `#!cpp double`/`#!cpp int64_t` the way `#!cpp get<T>()` (and
  [`basic_json::parse()`](../api/basic_json/parse.md)) would.

Both results are only valid as long as the view — and, for a string with no escapes, the borrowed source text — is.

## Writing generic code

A view's type names its `BasicJsonType` and its [`view_mode`](../api/view_mode.md):
[`json_view`](../api/json_view.md) is `#!cpp basic_json_view<json, view_mode::read_only>`, and
[`json_editable_view`](../api/json_editable_view.md) is `#!cpp basic_json_view<json, view_mode::editable>`. These are
different types. The only conversion between them turns a view of a read-only document into a view of an editable
document of the same `BasicJsonType`, so a function written for one shortcut accepts few other views:

```cpp
void print_names(json_view v);           // accepts neither an ordered_json_view nor a json_editable_view
void print_names(json_editable_view v);  // also accepts a json_view, but no ordered_json_view
```

This is the same pitfall as a `to_json`/`from_json` written for `json` instead of any `BasicJsonType`, which then does
not work for `ordered_json`. The shortcuts are for declaring documents and views; a function that takes a view names
the views it accepts with a template:

```cpp
// views of editable documents only
template<typename BasicJsonType>
void f(basic_json_view<BasicJsonType, view_mode::editable> v);

// views of read-only documents only
template<typename BasicJsonType>
void f(basic_json_view<BasicJsonType, view_mode::read_only> v);

// views of either document type
template<typename BasicJsonType, view_mode Mode>
void f(basic_json_view<BasicJsonType, Mode> v);
```

Views are passed by value: they are two pointers, cheap to copy, like a `#!cpp std::string_view`. A `const&` works as
well, but a non-`const` reference does not bind to the views that [`root()`](../api/basic_json_document/root.md),
[`operator[]`](../api/basic_json_view/operator%5B%5D.md), and [`at()`](../api/basic_json_view/at.md) return, so
`#!cpp f(doc.root())` would not compile.

There is no conversion from an editable view to a read-only one, by design: the mode decides how a view walks the
index. A read-only view reads a container in place, while a view of an editable document follows the links that edits
leave behind, so a read-only view of an edited document would read stale values. The other direction is safe: a
read-only document has no edits, so a view of it [converts](../api/basic_json_view/basic_json_view.md) to an
editable view, which reads it like an editable document before its first edit. A template deduces the mode without
conversions, so the template forms above still accept only the modes they name. Views of both modes compare with
[`operator==`](../api/basic_json_view/operator_eq.md).

[`is_json_view<T>`](../api/is_json_view.md) tells views from other types, for constraints that cannot be written as a
`basic_json_view<...>` parameter.

### A `from_json()` that reads views

[`get<T>()`](../api/basic_json_view/get.md) on a view calls `T`'s `from_json()` with the view itself if that
`from_json()` accepts views, and with [`materialize()`](../api/basic_json_view/materialize.md) otherwise. The
`from_json()` functions of the [`NLOHMANN_DEFINE_TYPE_*`](../api/macros/nlohmann_define_type_intrusive.md),
[`NLOHMANN_DEFINE_DERIVED_TYPE_*`](../api/macros/nlohmann_define_derived_type.md), and
[`NLOHMANN_JSON_SERIALIZE_ENUM`](../api/macros/nlohmann_json_serialize_enum.md) macros, and those of the library
for the standard types, accept views, so these types need nothing else. For decoding the statuses of
twitter.json into structs, reading the view is about 5 times faster than `#!cpp materialize().get<T>()`.

A hand-written `from_json()` reads views if it is constrained to `json` values and views:

```cpp
template < typename J, typename std::enable_if <
               nlohmann::is_json_view<J>::value || std::is_same<J, nlohmann::json>::value, int >::type = 0 >
void from_json(const J& j, person& p)
{
    p.name = j.at("name").template get<std::string>();
    p.age = j.at("age").template get<int>();
}
```

Its body may only use what views and `basic_json` have in common: the type checks, `at()`, `operator[]`, `contains()`,
`value()`, `size()`, iteration and `items()`, and `get<T>()`/`get_to()`. An unconstrained
`#!cpp template<typename BasicJsonType> void from_json(const BasicJsonType& j, person& p)`, as in
[arbitrary type conversions](arbitrary_types.md), is never called with a view, as it might use `basic_json` functions
a view does not have; such a type is converted through `materialize()`. A `from_json()` for `json` only is
converted through `materialize()` as well.

Two things differ when a `from_json()` reads the view:

- **Duplicate keys.** Members looked up by name (`at()`, `value()`, ... and thus the macros) find the **first** member
  with a repeated key, see [Duplicate keys](#duplicate-keys); `#!cpp materialize().get<T>()` would see the last one.
  Containers built from an object, such as `#!cpp std::map`, keep the **last** value either way, as
  [`parse()`](../api/basic_json/parse.md) does.
- **[`JSON_DIAGNOSTICS`](../api/macros/json_diagnostics.md).** Exceptions thrown by the view carry no path to the
  value.

`to_json()` is unaffected: it writes `basic_json` values, never views.

## Writing a view back

[`dump()`](../api/basic_json_view/dump.md) serializes a view directly from the flat index, without ever building a
`basic_json` value. An object's members are written in document order, not sorted by key, and *every* occurrence of a
repeated key is written, not only the last one — the same two ways [iteration](#what-is-different) already differs
from a [`materialize()`](../api/basic_json_view/materialize.md)d value, see [Duplicate keys](#duplicate-keys).
`#!cpp materialize().dump()` gives a different result in both respects for a `json_view`.

By default, numbers are written the way [`basic_json::dump()`](../api/basic_json/dump.md) would.
[`number_format::source`](../api/basic_json_view/number_format.md) instead copies every number exactly as it was
written in the source text — a price like `#!cpp 19.90`, a long order or account ID with more digits than any number
type holds, or a high-precision coordinate — something `basic_json` cannot do at all, since parsing already reduces
a number to its parsed `#!cpp double`/`#!cpp int64_t` value.

[`operator<<`](../api/basic_json_view/operator_ltlt.md) writes a view to a stream the way `basic_json`'s does, using
the stream's `width`/`fill` for indentation.

## Editing a document

Everything above is read-only: a `json_document`/`json_view` lets you look at a parsed text without copying it, but
not change it. [`basic_json_document<BasicJsonType, view_mode::editable>`](../api/basic_json_document/index.md) — more conveniently
spelled [`json_editable_document`](../api/json_editable_document.md) or
[`ordered_json_editable_document`](../api/ordered_json_editable_document.md) — also lets you
[`set`](../api/basic_json_document/set.md) a value, [`push_back`](../api/basic_json_document/push_back.md) onto or
[`insert`](../api/basic_json_document/insert.md) into an array, and [`erase`](../api/basic_json_document/erase.md)
an object member or an array element, still without ever building a `basic_json` tree for parts you do not touch.

The [mode](../api/view_mode.md) defaults to `#!cpp view_mode::read_only`, so `json_document`/`ordered_json_document` are unaffected — they carry
none of the bookkeeping edits need, and calling `set`/`push_back`/`insert`/`erase` on one is a compile error, not a
runtime one.

### Why: editing without reformatting

The `#!cpp 19.90` price from [above](#writing-a-view-back) is exactly the kind of value that makes editing a `json`
or `ordered_json` value in place lossy. Say you parse a configuration file, patch one field, and write it back:

- **`json`** re-sorts every key on the way in (`object_t` is a `#!cpp std::map`) and rewrites every number to its
  shortest round-trip form on the way out — a one-field patch turns into a diff that reorders the whole file and
  rewrites `#!cpp 19.90` to `#!cpp 19.9`.
- **`ordered_json`** keeps the key order, but still rewrites every number the same way: parsing has already reduced
  it to a `#!cpp double`/`#!cpp int64_t`, and there is no way back to how it was spelled in the source text.

The patch of the example below (set `"host"`, add `"retries"`) written back by each of them:

<div class="nj-jsonview-cmp" role="group" aria-label="The same patch written back by json, ordered_json, and json_editable_document">
<div><p class="nj-jsonview-cmp-h"><code>json</code></p><p class="nj-jsonview-cmp-v">keys sorted, numbers rewritten</p><pre>{<span class="nj-jsonview-bad">"host"</span>:"db2",
 "name":"cache",
 "port":6379,
 "price":<span class="nj-jsonview-bad">19.9</span>,
 "retries":3}</pre></div>
<div><p class="nj-jsonview-cmp-h"><code>ordered_json</code></p><p class="nj-jsonview-cmp-v">key order kept, numbers rewritten</p><pre>{"name":"cache",
 "host":"db2",
 "port":6379,
 "price":<span class="nj-jsonview-bad">19.9</span>,
 "retries":3}</pre></div>
<div class="nj-jsonview-cmp--best"><p class="nj-jsonview-cmp-h"><code>json_editable_document</code></p><p class="nj-jsonview-cmp-v">order and spelling kept</p><pre>{"name":"cache",
 "host":"db2",
 "port":6379,
 "price":<span class="nj-jsonview-ok">19.90</span>,
 "retries":3}</pre></div>
</div>

An editable document keeps both. [`dump()`](../api/basic_json_view/dump.md) of an edited document writes members in
document order — a member [`set`](../api/basic_json_document/set.md) added goes at the end, exactly where it was
inserted, and an [`erase`](../api/basic_json_document/erase.md)d member simply leaves a gap: everything around it
keeps its place — and [`number_format::source`](../api/basic_json_view/number_format.md) keeps the exact spelling
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

The source text itself is **never written**, and the parsed index never moves — a value keeps the node it was
parsed into for as long as it is not itself replaced. So every [view](../api/basic_json_view/index.md) taken before
an edit, including a previously obtained [`root()`](../api/basic_json_document/root.md), stays valid and, if it
still refers to the edited value, sees the edit; a view of a value a later edit drops or replaces just keeps showing
what it last held. New values go to storage the document allocates and owns on demand. The one thing an edit does
invalidate is the **iterators** taken over an edited array or object: the first time an element is added to it,
inserted into it, erased from it, or replaced by a value that spans a different number of nodes, its elements move from the parsed, fixed layout to a growable block of links
so that [`push_back`](../api/basic_json_document/push_back.md) can later grow it in amortized constant time —
existing elements are not touched, but an iterator that was walking the old layout no longer matches. A string
obtained with
[`get_string()`](../api/basic_json_view/get_string.md) is unaffected either way and stays valid across further
edits. See [`basic_json_document`'s Edits](../api/basic_json_document/index.md#edits) for the details, and
[`set`'s Exception safety](../api/basic_json_document/set.md#exception-safety) for what an edit guarantees if it
throws (the *basic* guarantee, not the strong one `dump()` and the read-only functions provide). How edits are kept in
the index is described in the [architecture overview](../home/architecture.md#node-index-of-json-views).

Step through the edits of a small document (the node fields follow the [architecture overview](../home/architecture.md#node-index-of-json-views)):

<div class="nj-jsonview-steps" data-nj-jsonview-steps>
<figure class="nj-jsonview-step" data-label="After parsing">
<div class="nj-jsonview-scroll">
--8<-- "images/json_view_edit_0.svg"
</div>
<figcaption>Step 1 of 5. After parsing: nine nodes in the parsed index, no owned storage yet.</figcaption>
</figure>
<figure class="nj-jsonview-step" data-label="set an existing member">
<div class="nj-jsonview-scroll">
--8<-- "images/json_view_edit_1.svg"
</div>
<figcaption>Step 2 of 5. <code>doc.set(doc.root(), "port", 6380)</code> overwrites the node of the integer in place; no member is added or removed, so the object keeps its parsed layout.</figcaption>
</figure>
<figure class="nj-jsonview-step" data-label="erase an array element">
<div class="nj-jsonview-scroll">
--8<-- "images/json_view_edit_2.svg"
</div>
<figcaption>Step 3 of 5. <code>doc.erase(doc.root()["tags"], 0)</code>: the array is edited for the first time, so its elements move to a block of links in owned storage. The node of <code>"eu"</code> stays in the index, but nothing refers to it any more; iterators over the array taken before are invalid.</figcaption>
</figure>
<figure class="nj-jsonview-step" data-label="push_back onto the array">
<div class="nj-jsonview-scroll">
--8<-- "images/json_view_edit_3.svg"
</div>
<figcaption>Step 4 of 5. <code>doc.push_back(doc.root()["tags"], "new")</code>: the new string gets its own node, its text goes to the buffer of edited text, and a link to it is appended to the block of the array.</figcaption>
</figure>
<figure class="nj-jsonview-step" data-label="set a new member">
<div class="nj-jsonview-scroll">
--8<-- "images/json_view_edit_4.svg"
</div>
<figcaption>Step 5 of 5. <code>doc.set(doc.root(), "retries", 3)</code>: a new member, so the object moves to a block too: copies of its keys, links to the values it already had, then the new key and a link to the new integer.</figcaption>
</figure>
</div>

<p class="nj-caption" markdown>The node index and the owned storage of the document after each of five edits. Use *Back*, *Next*, or the numbered buttons to switch between the steps; without JavaScript all steps are shown one below the other.</p>

## Images

[`save()`](../api/basic_json_document/save.md) writes a document as an *image*: a byte buffer that
[`load()`](../api/basic_json_document/load.md) reads back into a document without parsing — no lexing, no building
the node index, nothing but copying the nodes and pointing the text and the decoded strings at the image. Where
[`parse_copy()`](../api/basic_json_document/parse_copy.md) still has to scan the whole input,
[`load()`](../api/basic_json_document/load.md) turns that scan into a copy of the node index alone.

**Why.** A document that is parsed once and then read many times — a configuration loaded at startup, a template
rendered on every request, a large reference dataset a worker process needs in memory — pays for parsing once but
can amortize [`save()`](../api/basic_json_document/save.md)'s cost across every later load. That makes images useful
for a cache: save a document the first time it is parsed (to a file, a shared-memory segment, an in-process cache),
and [`load()`](../api/basic_json_document/load.md) it on every later use instead of parsing the source text again.
They are just as useful for handing a parsed document to another process (or a forked worker) running the same build
of the library, since [`load()`](../api/basic_json_document/load.md) turns the transfer into a copy of the node index
plus pointers into the received bytes, not a re-parse.

**Choosing a check.** [`load()`](../api/basic_json_document/load.md) takes an
[`image_check`](../api/basic_json_document/load.md#image_check) that trades validation against speed:
`image_check::full` (the default) checks everything the parser itself guarantees, so a checked image is exactly as
safe to read and serialize as a freshly parsed document — the right choice whenever the image did not come straight
from this process's own [`save()`](../api/basic_json_document/save.md), such as a file or a network peer.
`image_check::bounds` only checks structure and bounds — cheaper, since it skips scanning the text and the decoded
strings — and fits a cache the process trusts, one it wrote and reads back itself. `image_check::none` skips
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
    stable. It is little-endian only (on big-endian targets, `save()` and `load()` do not exist), and tied to the
    library build that wrote it — use it to cache a document or to hand one to another process running the *same*
    build, not as a long-term storage format; keep the original JSON text if a saved document needs to be readable by
    a future library version.

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
| **Typical use** | general-purpose JSON handling: config, request/response bodies you build or modify, anything you hold onto | validating or projecting a text into your own data structure without ever holding the whole thing as JSON | large or high-volume input where you only need part of it, or need it repeatedly, and can keep the source text (or a copy) alive for as long as the document lives | a document you read, patch a few fields of, and write back — a configuration file, for instance — where the rest of it should come back exactly as it was |
| **Caching/reload** | not applicable — re-parse, or roll your own serialization | not applicable | [`save()`](../api/basic_json_document/save.md)/[`load()`](../api/basic_json_document/load.md): cache the parsed index as an image and reload it without parsing | same, saving the document's current — possibly edited — state |

<p class="nj-table-caption" markdown>Each column is one way to work with JSON in this library, and each row compares one property of them.</p>

## See also

- [`basic_json_document`](../api/basic_json_document/index.md) - the document that owns the parsed index (parse, access, images, edits)
- [`basic_json_view`](../api/basic_json_view/index.md) - the non-owning handle to a value in a document
- [`json_document`](../api/json_document.md) - and [`ordered_json_document`](../api/ordered_json_document.md) - the read-only documents
- [`json_editable_document`](../api/json_editable_document.md) - and [`ordered_json_editable_document`](../api/ordered_json_editable_document.md) - the documents that can be edited in place
- [Architecture](../home/architecture.md#node-index-of-json-views) - the layout of the node index
- [SAX interface](parsing/sax_interface.md) - event-based parsing without building a tree
- [Performance](performance.md) - benchmarks and tuning of parsing and serialization
- [Large, Streamed, and Partial Input](parsing/large_and_partial_input.md) - reading only the part of a text you need

## Version history

- Added in version 3.13.0.
