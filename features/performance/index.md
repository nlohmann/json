# Performance

Speed was never the primary goal of this library. The [design goals](https://json.nlohmann.me/home/design_goals/index.md) page says so plainly: "There are certainly faster JSON libraries out there." Intuitive syntax, trivial integration, and thorough testing came first. If a hard real-time budget or the last percent of throughput matters more than convenience, a [faster, more specialized library](https://github.com/miloyip/nativejson-benchmark#parsing-time) may be a better fit.

That said, how you use this library still makes a measurable difference. This page collects practical, code-verified techniques for reducing time, memory, and compile-time cost -- without repeating the detailed pages it links to.

## Parsing input

[`parse`](https://json.nlohmann.me/api/basic_json/parse/index.md) accepts a string, a pair of iterators, a container, a `std::istream`, or a `FILE*` (see [Parsing](https://json.nlohmann.me/features/parsing/#input)). Internally, every input is wrapped in an [input adapter](https://json.nlohmann.me/home/architecture/#input-adapters), and not all adapters are equally fast.

For inputs backed by contiguous, single-byte memory -- a `std::string`, a `std::vector<char>`, a string literal, or a pointer range -- the library uses `iterator_input_adapter`, wrapped in a raw pointer so the fast paths below apply on every supported standard. This adapter exposes two optimizations the lexer detects at compile time:

- it can reconstruct already-consumed input on demand for error messages, instead of copying every character as it is read, and
- the lexer can scan ordinary string characters, numbers, and indentation directly out of the buffer, several bytes at a time, rather than one character (and one function call) at a time.

A `std::istream` (including `std::ifstream`) gets the same bulk scanning: `input_stream_adapter` scans the characters its stream buffer already holds (the *get area*) and asks the stream buffer for more only when they are used up. Nothing is read ahead, so the stream is left exactly where it would be after reading one character at a time, and [`operator>>`](https://json.nlohmann.me/api/operator_gtgt/index.md) can still read several values from one stream. A stream buffer without a get area is read one character at a time. A `FILE*` is still read one character at a time, but `file_input_adapter` locks the file once per parse instead of once per character. See [input sources and performance](https://json.nlohmann.me/features/parsing/#input-sources-and-performance) for the full table. According to the description of [#5828](https://github.com/nlohmann/json/pull/5828), parsing from a stream is within about 10 to 20 % of parsing an equivalent `std::string`.

Inputs that are still read one character at a time: iterator ranges that are not contiguous (e.g. `std::list<char>` or `std::istreambuf_iterator<char>`), wide strings, and user-defined adapters. An iterator pair over non-contiguous but random-access storage (e.g. `std::deque<char>::iterator`) gets the first optimization but not the second, since the byte-scanning fast path requires contiguous storage.

Practically: a file can be passed directly to `parse`, which also avoids the memory for a copy of the file. Reading it into a string first is no longer necessary for speed:

```
// fast: the stream buffer's get area is scanned in bulk
std::ifstream f("example.json");
json j = json::parse(f);
```

Two macros switch the stream optimizations off without changing any result: [`JSON_DISABLE_STREAM_BULK_SCAN`](https://json.nlohmann.me/api/macros/json_disable_stream_bulk_scan/index.md) for stream buffers that do not follow the usual `std::streambuf` contract, and [`JSON_DISABLE_UNLOCKED_FILE_IO`](https://json.nlohmann.me/api/macros/json_disable_unlocked_file_io/index.md) for programs in which another thread must use the same `FILE` object while it is parsed.

For contiguous input with many non-ASCII characters, [`JSON_USE_SIMDUTF`](https://json.nlohmann.me/api/macros/json_use_simdutf/index.md) can additionally speed up UTF-8 validation by using the [simdutf](https://github.com/simdutf/simdutf) library instead of the built-in scalar validator; streaming inputs (files, `std::istream`, wide strings, user-defined adapters) always use the scalar path regardless of this macro.

## Large documents

Parsing always produces SAX events internally; [`parse`](https://json.nlohmann.me/api/basic_json/parse/index.md) simply feeds them to a consumer that builds a complete `basic_json` value tree (a DOM) in memory. For documents too large to comfortably hold as a DOM, three alternatives avoid building it:

- Implement the [SAX interface](https://json.nlohmann.me/features/parsing/sax_interface/index.md) directly and pass it to [`sax_parse`](https://json.nlohmann.me/api/basic_json/sax_parse/index.md); only the parts of the input you choose to keep ever become `basic_json` values.
- Pass a [parser callback](https://json.nlohmann.me/features/parsing/parser_callbacks/index.md) to `parse`. This still builds a DOM, but the callback can discard finished elements as soon as they are handled, so memory usage stays bounded by one element (plus the unparsed remainder of the input) instead of the whole document -- see the [recipe for streaming a large homogeneous array](https://json.nlohmann.me/features/parsing/parser_callbacks/#recipe-streaming-a-large-homogeneous-array).
- Parse into a [`json_document`](https://json.nlohmann.me/features/json_view/index.md) (`<nlohmann/json_view.hpp>`) instead of a `basic_json`. It keeps the input text and builds a flat index of 16 bytes per value; strings and floating-point numbers are not copied, but read from the text when needed. Read-only [views](https://json.nlohmann.me/api/basic_json_view/index.md) give the familiar element access, and only the parts you [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) become `basic_json` values. A document that borrows the text instead of owning a copy needs the text to outlive it; see [choosing between `json`, the SAX interface, and `json_view`](https://json.nlohmann.me/features/json_view/#choosing-between-json-ordered_json-the-sax-interface-and-json_view).

If the data is naturally record-oriented, consider [JSON Lines](https://json.nlohmann.me/features/parsing/json_lines/index.md) instead of one large JSON document: reading and parsing it line by line with `std::getline` means only one line's value is ever in memory at a time, and a malformed line does not invalidate lines already processed.

## Binary formats

JSON text is not a compact format. If the data is only exchanged between programs (not read by humans), the [binary formats](https://json.nlohmann.me/features/binary_formats/index.md) -- BJData, BON8, BSON, CBOR, MessagePack, and UBJSON -- encode the same values more compactly, which reduces both the bytes transferred and, for most of them, the work needed to parse them back. The [size comparison](https://json.nlohmann.me/features/binary_formats/#sizes) on that page, measured against minified JSON for four reference documents, shows the effect varies a lot by document shape: CBOR and MessagePack come out at 50.5% of the minified JSON size for the numeric-array-heavy `canada.json`, but only around 87-88% for the string-heavy `jeopardy.json`, where there is less numeric data to encode more compactly. BON8 is the most compact option in that comparison for text-heavy documents (63.5%-87.5%), at the cost of an [incomplete serializer](https://json.nlohmann.me/features/binary_formats/#completeness) (no unsigned integers above int64). Which format -- and whether it is worth the loss of human readability at all -- depends on the actual data; see the [comparison tables](https://json.nlohmann.me/features/binary_formats/#comparison) before choosing one.

## Object type: `json` vs. `ordered_json`

The default [`json`](https://json.nlohmann.me/api/json/index.md) type stores object keys in a `std::map`, giving logarithmic-time lookup, insertion, and erasure, at the cost of sorting keys alphabetically rather than preserving insertion order (see [Object Order](https://json.nlohmann.me/features/object_order/index.md)). [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md) uses [`nlohmann::ordered_map`](https://json.nlohmann.me/api/ordered_map/index.md) instead, a `std::vector`-backed container with no lookup index: every key-based operation is a **linear scan**, so building an object of `n` distinct keys costs **O(n²)** in total -- this applies equally to inserting keys one by one and to parsing an object, since the parser inserts each key as it is read. The [measurements on the `ordered_map` page](https://json.nlohmann.me/api/ordered_map/#complexity) show this is negligible at typical object sizes (2000 keys: 0.7 ms for `json` vs. 3.6 ms for `ordered_json`, a 5x factor) but grows steeply for large, machine-generated objects (16 000 keys: 3.3 ms vs. 181.6 ms, a 54x factor).

If insertion order matters *and* an object routinely has many thousands of keys, `ordered_json`'s quadratic build cost may not be acceptable. The library's [`ObjectType` template parameter](https://json.nlohmann.me/features/types/template_parameters/#objecttype) can be set to a different container instead: `nlohmann::fifo_map` keeps insertion order with a real lookup index (avoiding the quadratic cost), while `std::unordered_map`, `boost::unordered_flat_map`, `absl::flat_hash_map`, and similar hash maps trade insertion order for average-case constant-time lookup (through an adapter, since their template argument order does not match what `basic_json` expects) -- see [Object Order](https://json.nlohmann.me/features/object_order/#alternative-behavior-preserve-insertion-order) for the full list.

## Avoiding copies

- **Move instead of copy.** Constructing a `basic_json` from an existing one is [linear in its size](https://json.nlohmann.me/api/basic_json/basic_json/#complexity) for the copy constructor but [constant](https://json.nlohmann.me/api/basic_json/basic_json/#complexity) for the move constructor. The same applies to assigning a large `std::string`, `std::vector`, or other container into a value: pass it as `std::move(x)` rather than `x` whenever `x` is no longer needed afterwards.
- **Access without copying.** [`get<T>()`](https://json.nlohmann.me/api/basic_json/get/index.md) returns a copy of the stored value converted to `T`. When a reference or pointer to the value already stored inside the `basic_json` is enough, [`get_ref()`](https://json.nlohmann.me/api/basic_json/get_ref/index.md) and [`get_ptr()`](https://json.nlohmann.me/api/basic_json/get_ptr/index.md) access it directly: both pages state, word for word, "No copies are made." -- at the cost of that reference or pointer becoming invalid once the underlying value changes.
- **Iterate by reference.** `basic_json::iterator::operator*()` returns a `reference` (an alias for `basic_json&`), but a range-based for loop with a by-value loop variable (`for (auto el : j)`) still copies each element, because plain `auto` drops the reference. Write `for (const auto& el : j)` (or `auto&` for a mutable loop), and use [`items()`](https://json.nlohmann.me/api/basic_json/items/index.md) the same way when the key is needed too -- its own examples use `for (auto& el : j.items())`.
- **Construct in place.** [`emplace_back()`](https://json.nlohmann.me/api/basic_json/emplace_back/index.md) (arrays, amortized constant time) and [`emplace()`](https://json.nlohmann.me/api/basic_json/emplace/index.md) (objects, logarithmic in the size of the container for `json`) forward their arguments directly to a `basic_json` constructor, rather than requiring a temporary value to be constructed and then copied or moved in. [`push_back()`](https://json.nlohmann.me/api/basic_json/push_back/index.md) has an rvalue overload (`push_back(basic_json&&)`) for a value that already exists: `j.push_back(std::move(value))` moves it in instead of copying it.
- **Skip the bounds check when it is redundant.** [`at()`](https://json.nlohmann.me/api/basic_json/at/index.md) and [`operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md) have the same complexity (constant for a valid array index, logarithmic for an object key in `json`) -- the difference is that `at()` additionally checks the key or index and throws if it is invalid, while `operator[]` does not (see [unchecked access](https://json.nlohmann.me/features/element_access/unchecked_access/index.md) and [checked access](https://json.nlohmann.me/features/element_access/checked_access/index.md)). Prefer `operator[]` when the surrounding code has already established that the access is valid.
- **Reserve array capacity.** `basic_json` has no public `reserve()`, but when building a large array incrementally with a known final size, [`get_ref()`](https://json.nlohmann.me/api/basic_json/get_ref/index.md) exposes the underlying `array_t` so it can be reserved directly -- see ["reserving array capacity"](https://json.nlohmann.me/features/element_access/unchecked_access/#performance-reserving-array-capacity) for the one-line recipe.

## Serialization

[`dump()`](https://json.nlohmann.me/api/basic_json/dump/index.md) with the default `indent = -1` selects "the most compact representation" (word for word from the page); any non-negative `indent` pretty-prints instead, which is more readable but produces more bytes and more work. `dump()` builds and returns a complete `string_t` containing the whole serialization. [`operator<<`](https://json.nlohmann.me/api/operator_ltlt/index.md) writes directly to a `std::ostream` instead, through the same serializer, but without ever materializing that intermediate string -- so if the destination is a stream (a file, or `std::cout`), `os << j;` avoids the allocation and copy that `os << j.dump();` would incur for large values.

## Diagnostics overhead

Two opt-in macros add diagnostic information to exceptions and to every value, at a cost that is only worth paying while it is in use:

- [`JSON_DIAGNOSTICS`](https://json.nlohmann.me/api/macros/json_diagnostics/index.md) adds a JSON Pointer to exception messages, pointing at the value that triggered the exception. Quoting the page directly: "enabling this macro increases the size of every JSON value by one pointer and adds some runtime overhead" -- every value gains a parent pointer that has to be kept up to date as the document is built and modified.
- [`JSON_DIAGNOSTIC_POSITIONS`](https://json.nlohmann.me/api/macros/json_diagnostic_positions/index.md) adds [`start_pos()`](https://json.nlohmann.me/api/basic_json/start_pos/index.md) and [`end_pos()`](https://json.nlohmann.me/api/basic_json/end_pos/index.md), the byte offsets a value occupied in its parsed input. Quoting the page: "enabling this macro increases the size of every JSON value by two `std::size_t` fields and adds slight runtime overhead to parsing, copying JSON value objects, and the generation of error messages for exceptions."

Both default to off. Enable them where better diagnostics are worth the overhead (for example, while validating untrusted input, or in a debug build), and keep them off in a release build that does not need them.

## Compile time

[`<nlohmann/json_fwd.hpp>`](https://json.nlohmann.me/home/architecture/#source-layout) forward-declares [`basic_json`](https://json.nlohmann.me/api/basic_json/index.md), [`json`](https://json.nlohmann.me/api/json/index.md), [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md), [`json_pointer`](https://json.nlohmann.me/api/json_pointer/index.md), and [`adl_serializer`](https://json.nlohmann.me/api/adl_serializer/index.md), pulling in only a handful of lightweight standard headers instead of the full `json.hpp`. A header that only needs to *name* `nlohmann::json` -- in a function signature or a class member declaration, for instance -- can include `json_fwd.hpp` and leave `#include <nlohmann/json.hpp>` to the source files that actually parse, build, or serialize values, the same way a project would forward-declare any other heavy class to keep it out of widely-included headers:

```
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

One caveat: ABI-affecting macros such as `JSON_DIAGNOSTICS` and `JSON_DIAGNOSTIC_POSITIONS` are encoded into the library's [inline namespace name](https://json.nlohmann.me/features/namespace/#limitations). Every translation unit -- whether it includes `json_fwd.hpp` or the full header -- must define them the same way, or linking fails with undefined references instead of a compile error.

If I/O support is not needed at all, [`JSON_NO_IO`](https://json.nlohmann.me/api/macros/json_no_io/index.md) excludes `<cstdio>`, `<ios>`, `<iosfwd>`, `<istream>`, and `<ostream>` outright and drops the `std::istream`/`FILE*` `parse` overloads and [`operator<<`](https://json.nlohmann.me/api/operator_ltlt/index.md) that depend on them (`dump()` itself is unaffected, since it only returns a string); it exists for environments where those headers are unavailable (such as Intel SGX), and as a side effect those headers are then never processed by the compiler at all.

## See also

- [Design goals](https://json.nlohmann.me/home/design_goals/index.md) - why this library does not optimize for speed first
- [Architecture](https://json.nlohmann.me/home/architecture/index.md) - how input adapters, the lexer, and the serializer fit together
- [Parsing](https://json.nlohmann.me/features/parsing/index.md) - the available parsing functions and inputs
- [SAX interface](https://json.nlohmann.me/features/parsing/sax_interface/index.md) - parse without building a DOM
- [Zero-copy JSON views](https://json.nlohmann.me/features/json_view/index.md) - parse into a flat index of the text and read it without building a DOM
- [Binary formats](https://json.nlohmann.me/features/binary_formats/index.md) - compact alternatives to JSON text
- [Object Order](https://json.nlohmann.me/features/object_order/index.md) - `json` vs. `ordered_json` and other `ObjectType` choices
- [Template Parameter Requirements](https://json.nlohmann.me/features/types/template_parameters/index.md) - custom container and allocator types
- [Supported macros](https://json.nlohmann.me/features/macros/index.md) - overview of all configuration macros, including the diagnostics ones above
