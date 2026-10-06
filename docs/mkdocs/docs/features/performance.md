# Performance

Speed was never the primary goal of this library. The [design goals](../home/design_goals.md) page says so plainly:
"There are certainly faster JSON libraries out there." Intuitive syntax, trivial integration, and thorough testing came
first. If a hard real-time budget or the last percent of throughput matters more than convenience, a
[faster, more specialized library](https://github.com/miloyip/nativejson-benchmark#parsing-time) may be a better fit.

That said, how you use this library still makes a measurable difference. This page collects practical, code-verified
techniques for reducing time, memory, and compile-time cost -- without repeating the detailed pages it links to.

## Parsing input

[`parse`](../api/basic_json/parse.md) accepts a string, a pair of iterators, a container, a `#!cpp std::istream`, or a
`#!cpp FILE*` (see [Parsing](parsing/index.md#input)). Internally, every input is wrapped in an
[input adapter](../home/architecture.md#input-adapters), and not all adapters are equally fast.

For inputs backed by contiguous, single-byte memory -- a `#!cpp std::string`, a `#!cpp std::vector<char>`, a string
literal, or a pointer range -- the library uses `iterator_input_adapter`, wrapped in a raw pointer so the fast paths
below apply on every supported standard. This adapter exposes two optimizations the lexer detects at compile time:

- it can reconstruct already-consumed input on demand for error messages, instead of copying every character as it is
  read, and
- the lexer can scan ordinary string characters directly out of the buffer, several bytes at a time, rather than one
  character (and one function call) at a time.

A `#!cpp std::istream` (including `#!cpp std::ifstream`) or `#!cpp FILE*`, by contrast, is read through
`input_stream_adapter` or `file_input_adapter`, which read one character (or one block, for binary formats) at a time
and expose neither optimization -- the lexer falls back to the same byte-at-a-time path it uses for any
non-contiguous, general-purpose iterator range. An iterator pair over non-contiguous but random-access storage (e.g.
`#!cpp std::deque<char>::iterator`) gets the first optimization but not the second, since the byte-scanning fast path
additionally requires contiguous storage.

Practically: if the JSON text is already in memory, or small enough to read into memory, prefer passing a
`#!cpp std::string`, a `#!cpp std::vector<char>`, or a pointer range to `parse` over a `#!cpp std::istream`. For a
file, that means reading it into a string first and then parsing the string, rather than passing a
`#!cpp std::ifstream` directly to `parse` -- the latter never benefits from either optimization:

```cpp
// gets the contiguous fast paths
std::ifstream f("example.json");
std::string contents((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
json j = json::parse(contents);

// does not: input_stream_adapter has no fast path
std::ifstream f2("example.json");
json j2 = json::parse(f2);
```

For contiguous input with many non-ASCII characters, [`JSON_USE_SIMDUTF`](../api/macros/json_use_simdutf.md) can
additionally speed up UTF-8 validation by using the [simdutf](https://github.com/simdutf/simdutf) library instead of
the built-in scalar validator; streaming inputs (files, `#!cpp std::istream`, wide strings, user-defined adapters)
always use the scalar path regardless of this macro.

## Large documents

Parsing always produces SAX events internally; [`parse`](../api/basic_json/parse.md) simply feeds them to a consumer
that builds a complete `basic_json` value tree (a DOM) in memory. For documents too large to comfortably hold as
a DOM, three alternatives avoid building it:

- Implement the [SAX interface](parsing/sax_interface.md) directly and pass it to
  [`sax_parse`](../api/basic_json/sax_parse.md); only the parts of the input you choose to keep ever become
  `basic_json` values.
- Pass a [parser callback](parsing/parser_callbacks.md) to `parse`. This still builds a DOM, but the callback can
  discard finished elements as soon as they are handled, so memory usage stays bounded by one element (plus the
  unparsed remainder of the input) instead of the whole document -- see the [recipe for streaming a large homogeneous
  array](parsing/parser_callbacks.md#recipe-streaming-a-large-homogeneous-array).
- Parse into a [`json_document`](json_view.md) (`#!cpp <nlohmann/json_view.hpp>`) instead of a `basic_json`. It keeps
  the input text and builds a flat index of 16 bytes per value; strings and numbers are not copied, but read from the
  text when needed. Read-only [views](../api/basic_json_view/index.md) give the familiar element access, and only the
  parts you [`materialize()`](../api/basic_json_view/materialize.md) become `basic_json` values. A document that
  borrows the text instead of owning a copy needs the text to outlive it; see
  [choosing between `json`, the SAX interface, and `json_view`](json_view.md#choosing-between-json-ordered_json-the-sax-interface-and-json_view).

If the data is naturally record-oriented, consider [JSON Lines](parsing/json_lines.md) instead of one large JSON
document: reading and parsing it line by line with `#!cpp std::getline` means only one line's value is ever in memory
at a time, and a malformed line does not invalidate lines already processed.

## Binary formats

JSON text is not a compact format. If the data is only exchanged between programs (not read by humans), the
[binary formats](binary_formats/index.md) -- BJData, BON8, BSON, CBOR, MessagePack, and UBJSON -- encode the same
values more compactly, which reduces both the bytes transferred and, for most of them, the work needed to parse them
back. The [size comparison](binary_formats/index.md#sizes) on that page, measured against minified JSON for four
reference documents, shows the effect varies a lot by document shape: CBOR and MessagePack come out at 50.5% of the
minified JSON size for the numeric-array-heavy `canada.json`, but only around 87-88% for the string-heavy
`jeopardy.json`, where there is less numeric data to encode more compactly. BON8 is the most compact option in that
comparison for text-heavy documents (63.5%-87.5%), at the cost of an
[incomplete serializer](binary_formats/index.md#completeness) (no unsigned integers above int64). Which format -- and
whether it is worth the loss of human readability at all -- depends on the actual data; see the
[comparison tables](binary_formats/index.md#comparison) before choosing one.

## Object type: `json` vs. `ordered_json`

The default [`json`](../api/json.md) type stores object keys in a `#!cpp std::map`, giving logarithmic-time lookup,
insertion, and erasure, at the cost of sorting keys alphabetically rather than preserving insertion order (see
[Object Order](object_order.md)). [`ordered_json`](../api/ordered_json.md) uses
[`nlohmann::ordered_map`](../api/ordered_map.md) instead, a `#!cpp std::vector`-backed container with no lookup index:
every key-based operation is a **linear scan**, so building an object of `n` distinct keys costs **O(n²)** in total --
this applies equally to inserting keys one by one and to parsing an object, since the parser inserts each key as it is
read. The [measurements on the `ordered_map` page](../api/ordered_map.md#complexity) show this is
negligible at typical object sizes (2000 keys: 0.7 ms for `json` vs. 3.6 ms for `ordered_json`, a 5x factor) but grows
steeply for large, machine-generated objects (16 000 keys: 3.3 ms vs. 181.6 ms, a 54x factor).

If insertion order matters *and* an object routinely has many thousands of keys, `ordered_json`'s quadratic build cost
may not be acceptable. The library's [`ObjectType` template parameter](types/template_parameters.md#objecttype) can be
set to a different container instead: `#!cpp nlohmann::fifo_map` keeps insertion order with a real lookup index
(avoiding the quadratic cost), while `#!cpp std::unordered_map`, `#!cpp boost::unordered_flat_map`,
`#!cpp absl::flat_hash_map`, and similar hash maps trade insertion order for average-case constant-time lookup (through
an adapter, since their template argument order does not match what `basic_json` expects) -- see
[Object Order](object_order.md#alternative-behavior-preserve-insertion-order) for the full list.

## Avoiding copies

- **Move instead of copy.** Constructing a `basic_json` from an existing one is
  [linear in its size](../api/basic_json/basic_json.md#complexity) for the copy constructor but
  [constant](../api/basic_json/basic_json.md#complexity) for the move constructor. The same applies to assigning a
  large `#!cpp std::string`, `#!cpp std::vector`, or other container into a value: pass it as `#!cpp std::move(x)`
  rather than `x` whenever `x` is no longer needed afterwards.
- **Access without copying.** [`get<T>()`](../api/basic_json/get.md) returns a copy of the stored value converted to
  `T`. When a reference or pointer to the value already stored inside the `basic_json` is enough,
  [`get_ref()`](../api/basic_json/get_ref.md) and [`get_ptr()`](../api/basic_json/get_ptr.md) access it directly:
  both pages state, word for word, "No copies are made." -- at the cost of that reference or pointer becoming invalid
  once the underlying value changes.
- **Iterate by reference.** `#!cpp basic_json::iterator::operator*()` returns a `reference` (an alias for
  `#!cpp basic_json&`), but a range-based for loop with a by-value loop variable (`#!cpp for (auto el : j)`) still
  copies each element, because plain `#!cpp auto` drops the reference. Write `#!cpp for (const auto& el : j)` (or
  `#!cpp auto&` for a mutable loop), and use [`items()`](../api/basic_json/items.md) the same way when the key is
  needed too -- its own examples use `#!cpp for (auto& el : j.items())`.
- **Construct in place.** [`emplace_back()`](../api/basic_json/emplace_back.md) (arrays, amortized constant time) and
  [`emplace()`](../api/basic_json/emplace.md) (objects, logarithmic in the size of the container for `json`) forward
  their arguments directly to a `basic_json` constructor, rather than requiring a temporary value to be
  constructed and then copied or moved in. [`push_back()`](../api/basic_json/push_back.md) has an rvalue overload
  (`#!cpp push_back(basic_json&&)`) for a value that already exists: `#!cpp j.push_back(std::move(value))` moves it
  in instead of copying it.
- **Skip the bounds check when it is redundant.** [`at()`](../api/basic_json/at.md) and
  [`operator[]`](../api/basic_json/operator%5B%5D.md) have the same complexity (constant for a valid array index,
  logarithmic for an object key in `json`) -- the difference is that `at()` additionally checks the key or index and
  throws if it is invalid, while `operator[]` does not (see [unchecked access](element_access/unchecked_access.md) and
  [checked access](element_access/checked_access.md)). Prefer `operator[]` when the surrounding code has already
  established that the access is valid.
- **Reserve array capacity.** `basic_json` has no public `reserve()`, but when building a large array
  incrementally with a known final size, [`get_ref()`](../api/basic_json/get_ref.md) exposes the underlying
  `#!cpp array_t` so it can be reserved directly -- see
  ["reserving array capacity"](element_access/unchecked_access.md#performance-reserving-array-capacity) for the
  one-line recipe.

## Serialization

[`dump()`](../api/basic_json/dump.md) with the default `#!cpp indent = -1` selects "the most compact representation"
(word for word from the page); any non-negative `indent` pretty-prints instead, which is more readable but produces
more bytes and more work. `dump()` builds and returns a complete `#!cpp string_t` containing the whole serialization.
[`operator<<`](../api/operator_ltlt.md) writes directly to a `#!cpp std::ostream` instead, through the same
serializer, but without ever materializing that intermediate string -- so if the destination is a stream (a file, or
`#!cpp std::cout`), `#!cpp os << j;` avoids the allocation and copy that `#!cpp os << j.dump();` would incur for large
values.

## Diagnostics overhead

Two opt-in macros add diagnostic information to exceptions and to every value, at a cost that is only worth paying
while it is in use:

- [`JSON_DIAGNOSTICS`](../api/macros/json_diagnostics.md) adds a JSON Pointer to exception messages, pointing at the
  value that triggered the exception. Quoting the page directly: "enabling this macro increases the size of every
  JSON value by one pointer and adds some runtime overhead" -- every value gains a parent pointer that has to be kept
  up to date as the document is built and modified.
- [`JSON_DIAGNOSTIC_POSITIONS`](../api/macros/json_diagnostic_positions.md) adds
  [`start_pos()`](../api/basic_json/start_pos.md) and [`end_pos()`](../api/basic_json/end_pos.md), the byte offsets a
  value occupied in its parsed input. Quoting the page: "enabling this macro increases the size of every JSON value by
  two `std::size_t` fields and adds slight runtime overhead to parsing, copying JSON value objects, and the generation
  of error messages for exceptions."

Both default to off. Enable them where better diagnostics are worth the overhead (for example, while validating
untrusted input, or in a debug build), and keep them off in a release build that does not need them.

## Compile time

[`<nlohmann/json_fwd.hpp>`](../home/architecture.md#source-layout) forward-declares
[`basic_json`](../api/basic_json/index.md), [`json`](../api/json.md), [`ordered_json`](../api/ordered_json.md),
[`json_pointer`](../api/json_pointer/index.md), and [`adl_serializer`](../api/adl_serializer/index.md), pulling in only
a handful of lightweight standard headers instead of the full `json.hpp`. A header that only needs to *name*
`nlohmann::json` -- in a function signature or a class member declaration, for instance -- can include `json_fwd.hpp`
and leave `#!cpp #include <nlohmann/json.hpp>` to the source files that actually parse, build, or serialize values,
the same way a project would forward-declare any other heavy class to keep it out of widely-included headers:

```cpp
// my_type.hpp
#include <nlohmann/json_fwd.hpp>

class my_type
{
    nlohmann::json config() const;
};

// my_type.cpp
#include <nlohmann/json.hpp>
#include "my_type.hpp"

nlohmann::json my_type::config() const { /* ... */ }
```

One caveat: ABI-affecting macros such as `JSON_DIAGNOSTICS` and `JSON_DIAGNOSTIC_POSITIONS` are encoded into the
library's [inline namespace name](namespace.md#limitations). Every translation unit -- whether it includes
`json_fwd.hpp` or the full header -- must define them the same way, or linking fails with undefined references
instead of a compile error.

If I/O support is not needed at all, [`JSON_NO_IO`](../api/macros/json_no_io.md) excludes `<cstdio>`, `<ios>`,
`<iosfwd>`, `<istream>`, and `<ostream>` outright and drops the `#!cpp std::istream`/`#!cpp FILE*` `parse` overloads and
[`operator<<`](../api/operator_ltlt.md) that depend on them (`dump()` itself is unaffected, since it only returns a
string); it exists for environments where those headers are unavailable (such as Intel SGX), and as a side effect
those headers are then never processed by the compiler at all.

## See also

- [Design goals](../home/design_goals.md) - why this library does not optimize for speed first
- [Architecture](../home/architecture.md) - how input adapters, the lexer, and the serializer fit together
- [Parsing](parsing/index.md) - the available parsing functions and inputs
- [SAX interface](parsing/sax_interface.md) - parse without building a DOM
- [Zero-copy JSON views](json_view.md) - parse into a flat index of the text and read it without building a DOM
- [Binary formats](binary_formats/index.md) - compact alternatives to JSON text
- [Object Order](object_order.md) - `json` vs. `ordered_json` and other `ObjectType` choices
- [Template Parameter Requirements](types/template_parameters.md) - custom container and allocator types
- [Supported macros](macros.md) - overview of all configuration macros, including the diagnostics ones above
