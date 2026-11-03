# json_document against other JSON libraries

[`compare.py`](../compare.py) compares `json_document` with yyjson, simdjson and Boost.JSON. The programs here add
sonic-cpp, RapidJSON and Glaze in C++, and sonic-rs, simd-json and serde_json in Rust, for the post
[How 3.13.0 got faster](https://json.nlohmann.me/home/blog/how_3_13_0_got_faster/#how-it-compares). They are not
built by CMake or run by CI.

## What is measured

The programs compare **use cases**, not library functions. A library may implement a use case in every reasonable way
(another API, SAX events, in-situ parsing, a struct binding); each such way is a *variant*, named
`<library>: <variant>` (`yyjson: insitu (copy)`, `RapidJSON: SAX`, `nlohmann json_document: accept`). The report shows
each library's fastest correct variant. `nlohmann json` (`basic_json`) and `nlohmann json_document` (with
`json_view`) count as two libraries.

| use case | what it does |
|---|---|
| `validate` | is this text valid JSON? returns a bool |
| `sum` | visit every value, convert every number, touch every string and key; sum all numbers in document order |
| `select` | read a few fields of every record (the fields of `bench_view.cpp`, e.g. `id`, `user.screen_name` and `retweet_count` of every status) |
| `edit` | change some values of every record and write the document as compact JSON (see below) |
| `minify` | text in, compact text out |
| `write` | write a document parsed beforehand as compact JSON; only the writing is timed |

The edits:

| file | edit |
|---|---|
| `twitter.json` | for every element of `statuses`: `retweet_count` + 1, erase `entities`, add `"seen": true` |
| status | the same edit on the one status |
| `citm_catalog.json` | for every element of `performances`: `start` + 1, erase `seatMapImage`, add `"seen": true` |
| `canada.json` | `features[0].properties.name` = `"Kanada"`; append `[0.5,0.25]` to the first ring (`geometry.coordinates[0]`) of every feature |
| `jeopardy.json` | for every record: `value` = `null`, erase `air_date`, add `"seen": true` |

The files are `twitter.json`, `citm_catalog.json`, `canada.json` (nativejson-benchmark), `jeopardy.json`, the first
status of `twitter.json` (`status`; written by `json::dump()`, timed in batches of 200), and `twitter_min` and
`citm_catalog_min`: `twitter.json` and `citm_catalog.json` with all whitespace outside strings removed, built in memory at
startup by the same small function in both programs (`strip_ws`; the bytes inside strings are untouched). The minified
files use the select and edit of their originals.

### Input contract

The input is a `const std::string` holding the file, with at least 64 bytes of spare capacity (`reserve`), so libraries
that need padding (simdjson) can use it without a copy. A variant that modifies the input (in-situ parsing: yyjson
`YYJSON_READ_INSITU`, RapidJSON `ParseInsitu`, simd-json) copies it inside the timed call; its name says `(copy)`.
The C++ in-situ variants also run as `(copy untimed)`: the copy is made before the timer starts and freed after it
stops, as for a program that reads a file into a buffer it owns and no longer needs. They are reported but never
chosen as a library's best. `json_document`'s `parse_copy` is the opposite case: a document that owns a copy of its
text.
Each timed call starts from the text and frees everything it built, except variants named `(reused)` or
`(reused allocator)`, which keep a parser, document or allocator across calls (simdjson's reused parsers,
`json_document::read()`, Boost.JSON's reset `parser` and `basic_parser`, yyjson's dynamic allocator, RapidJSON's
user-buffer allocators, simd-json's buffers). These are reported but never chosen as a library's best;
`summarize.py` reports each library's best reused variant separately. In Rust, the input is the file as bytes (`&[u8]`), so every library
has to validate UTF-8 itself.

### Correctness rules

Before timing, every variant runs on the file and must produce the right result:

- `validate`: `true`.
- `sum`: the same number of values, the same number of string and key bytes, and a sum of all numbers that is
  bit-identical to `json_document`'s (document order), so every number is converted exactly; variants that visit
  objects in another order (`nlohmann json: parse`, simd-json and serde_json values) are compared within 1e-9.
- `select`: the same value as `json_document`. A variant that does not convert numbers (`(raw numbers)`,
  `(numbers: none)`) has to convert the numbers it selects exactly itself.
- `edit`, `minify`, `write`: the output, read with `json::parse`, compares equal (`==`) to the expected document (for
  `edit`, the edit applied to a `json` value; floats compare exactly, so every float must be written exactly). In
  Rust, `serde_json::Value` (with `float_roundtrip`) is the reference.

A variant that gives a wrong result on a file, or crashes on it, is printed as
`excluded: <file> <use case> | <variant> | <reason>` and not timed.

### Validation levels

Except for `write`, every variant is also probed with four malformed inputs derived from each file: the file
truncated by one byte (after trailing whitespace), the file followed by ` ]x` (trailing garbage), a stray `,` before
the first `}` (before the last `]` in a file without objects), and a `0xFF` byte inside a string value (the first in
the second half of the file, or the last one; never a key, so that a variant that accepts the byte still finds the
keys it looks up; a file without string values gets no `0xFF` probe). The probes run in a child process, so a crash is caught. The result is the
variant's *validation level*, printed in its cell (`sonic-cpp: Document [no UTF-8] 380.1us`):

| level | meaning |
|---|---|
| `full` | rejects all four probes |
| `no UTF-8` | rejects the structural probes, accepts the `0xFF` byte |
| `partial` | accepts the truncated input, the trailing garbage or the stray comma, or crashes on any probe |
| `n/a` | `write`: there is no input to validate (counts as `full`) |

What a variant accepts is printed as `level: <file> <use case> | <variant> | <level> | <what>`. A variant's level in
the summary is the worst it got for any file. UTF-8 validation is enabled where a library has a switch (RapidJSON
`kParseValidateEncodingFlag`; the `(no encoding check)` variants leave it off). sonic-cpp 1.0.2 cannot validate
UTF-8 at all; serde_json does not validate UTF-8 in the parts it skips (`IgnoredAny`, unknown struct fields) unless
the input is checked with `std::str::from_utf8` first (the `from_utf8 + ...` variants).

The sum and select reference values are printed as `check ... reference:` lines; `summarize.py` warns if the C++ and
Rust logs disagree.

The four probes do not cover everything a parser can get wrong. `--conformance <dir>` runs every `validate` variant
on every file of [JSONTestSuite](https://github.com/nst/JSONTestSuite)'s `test_parsing` (json_test_data has it as
`nst_json_testsuite2/test_parsing`) and prints `conformance: <file> | <variant> | accepted|rejected|crashed`; a `y_`
file must be accepted, an `n_` file rejected, and an `i_` file may go either way. bench_all runs each call in a child
process (a call that hangs for 60 s counts as crashed); a stack overflow aborts bench_rs, so `conformance-rs.sh`
runs it one file per process and, for a file that aborts, one variant per process (`CONF_VARIANT`). The trailing
garbage probe was added after this check: Glaze reads anything after the value unless `validate_trailing_whitespace`
is set.

### Variants

Level on the Mac in brackets where it is not `full` (`P` = partial, `U` = no UTF-8); every `write` variant is `n/a`.

| library | validate | sum | select | edit | minify | write |
|---|---|---|---|---|---|---|
| nlohmann json_document | `accept`, `parse`, `read (reused)` | `parse`, `parse_copy`, `read (reused)` | `parse`, `parse_copy`, `structs (from_json)`, `read (reused)` | `editable`, `editable (source numbers)` (`json_editable_document`: set/erase, `dump` with `number_format::source`) | `parse + dump`, `parse_copy + dump`, `parse + dump (source numbers)`, `read + dump (reused)` | `dump`, `dump (source numbers)` |
| nlohmann json | `accept`, `parse` | `parse`, `sax` | `parse`, `structs (from_json)` | `parse`, `ordered_json` | `parse + dump` | `dump` |
| yyjson | `read`, `insitu (copy)`, `insitu (copy untimed)`, `read (raw numbers)`, `read (reused allocator)` | `read`, `insitu (copy)`, `insitu (copy untimed)`, `read (reused allocator)` | `read`, `insitu (copy)`, `insitu (copy untimed)`, `read (raw numbers)`, `read (reused allocator)` | `mut copy`, `insitu (copy) + mut copy` (`yyjson_doc_mut_copy`), `insitu (copy untimed) + mut copy` | `read + write`, `insitu (copy) + write`, `insitu (copy untimed) + write`, `read (raw numbers) + write`, `read + write (reused allocator)` | `write` |
| simdjson | `DOM`, `DOM (reused)` | `DOM`, `DOM (reused)`, `On-Demand`, `On-Demand (reused)` | `DOM`, `DOM (reused)`, `On-Demand` [P], `On-Demand (reused)` [P], `On-Demand structs` [P], `On-Demand (key selectors)` [P] | n/a (no mutable document) | `DOM + to_string`, `DOM (reused) + to_string`, `minify` [P] | `to_string` |
| RapidJSON | `SAX` (null handler), `Document`, `insitu (copy)`, `insitu (copy untimed)`, `SAX (string stream)`, `SAX (default precision)`, `SAX (string stream, default precision)`, `SAX (raw numbers)`, `Document (reused allocator)` | `Document`, `SAX`, `insitu (copy)`, `insitu (copy untimed)`, `SAX (string stream)`, `Document (reused allocator)` | `Document`, `insitu (copy)`, `insitu (copy untimed)`, `Document (string stream)`, `Document (raw numbers)`, `Document (reused allocator)` | `Document`, `insitu (copy)`, `insitu (copy untimed)`, `Document (string stream)` | `Document + Writer`, `SAX to Writer`, `SAX to Writer (string stream)`, `SAX to Writer (raw numbers)`, `Document + Writer (reused allocator)` | `Writer` |
| RapidJSON, `(no encoding check)` | the same [U] | the same [U] | the same [U] | the same [U] | the same [U] | |
| sonic-cpp | `Document` [U] | `Document` [U] | `Document` [U] | `Document` [U] | `Document + Serialize` [U] | `Serialize` |
| Glaze | `validate_json`, `generic` [P], `generic (double)` [P], `generic (strict)`, `generic (double, strict)` | `generic` [P], `generic (double)` [P], `generic (strict)`, `generic (double, strict)`, `lazy_json` [P], `lazy_json (string_view)` (x) | `structs` [P], `structs (validate_skipped)`, `generic` [P], `generic (double)` [P], `generic (strict)`, `generic (double, strict)`, `lazy_json` [P], `lazy_json (string_view)` (x) | `generic` [P], `generic (double)` (x), `generic (strict)`, `generic (double, strict)` (x) | `generic` [P], `generic (double)` (x), `generic (strict)`, `generic (double, strict)` (x), `minify_json` [P] | `generic`, `generic (double)` (x), `generic (strict)`, `generic (double, strict)` (x) |
| Boost.JSON | `SAX` (`basic_parser`), `parse`, `SAX (numbers: none)`, `parse (numbers: none)`, `SAX (reused)`, `parser (reused)` | `parse`, `SAX`, `SAX (reused)`, `parser (reused)` | `parse`, `parse (numbers: none)` (x), `parser (reused)`, `parse_into structs` | `parse` | `parse + serialize`, `parser (reused) + serialize` | `serialize` |
| serde_json | `IgnoredAny` [U], `from_utf8 + IgnoredAny`, `Value` | `visitor`, `Value` | `structs` [U], `from_utf8 + structs`, `Value` | `Value` | `Value` | `Value` |
| sonic-rs | `IgnoredAny`, `Value` | `visitor`, `Value` | `structs`, `Value` | `Value` | `Value` | `Value` |
| simd-json | `tape (copy)`, `borrowed (copy)`, `tape (reused)` | `visitor (copy)`, `borrowed (copy)`, `borrowed (reused)` | `structs (copy)`, `borrowed (copy)` | `owned (copy)`, `borrowed (copy)` | `borrowed (copy)` | `borrowed` |

(x): excluded for a wrong result on some file, and so in the summary for every file: `generic (double)` loses the
64-bit ids of `twitter.json` when it writes them; `lazy_json (string_view)` reads the raw bytes of a string, so escaped
strings have the wrong length (`sum`, and the `"` in 19,077 `jeopardy.json` categories in `select`);
`numbers: none` reads every number as 0.

`structs` read into types that declare only the fields `select` uses and hold the same data: nlohmann/json's
`from_json()` of the `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE` macro (from a `json` value or from a `json_document`'s view)
reads into `nsel`, where the arrays and objects that are only counted (`seatCategories`, the values of `events`,
`coordinates`) are a `count_only` holding their size. Glaze reads into the same types (reflected; `count_only` has a
reader that skips and counts the elements; `error_on_unknown_keys = false`, and with `validate_skipped` to validate
what it skips), and so does simdjson On-Demand (`get<T>()` with `tag_invoke`, fields in document order,
`count_elements()`/`count_fields()`). serde derive reads into the same fields with a `Count` that counts with
`IgnoredAny` (and a `BTreeMap`, as `std::map`). Boost.JSON's `parse_into` has no type that skips any value, so its
counted members only count what it converts into them: `seatCategories` into a counting sequence of an empty described
struct, `coordinates` into three levels of counting sequences down to `double`, and the `events` values into an empty
described struct, so their members are not counted. `key selectors` are simdjson 5.0's `object::for_each<"k1",
...>`, which walks each object once and matches keys with a compile-time perfect hash. `visitor` is a serde
`DeserializeSeed` that sums without building a value; `SAX` and `sax` are the libraries' event interfaces with a
summing (or, for `validate`, an empty) handler. RapidJSON parses with `kParseFullPrecisionFlag` (correctly rounded
floats; without it, sums and written floats are wrong) and Boost.JSON with `number_precision::precise`, as every other
library rounds correctly by default; only `validate`, which reads no number, also has RapidJSON's `(default
precision)`. RapidJSON's `Document::Parse(data, size)` and our `SAX` read through `EncodedInputStream<MemoryStream>`;
`(string stream)` reads the NUL-terminated string through `StringStream`, as `Document::Parse(const char*)` does,
where RapidJSON has a SIMD string scanner (used only without `kParseValidateEncodingFlag`).

Variants named `(raw numbers)` or `(numbers: none)` use a library's mode that validates numbers without converting
them (yyjson `YYJSON_READ_NUMBER_AS_RAW`, RapidJSON `kParseNumbersAsStringsFlag`, Boost.JSON
`number_precision::none`), as `json_document` converts a number only when it is read. In `select` they convert the
selected numbers themselves (`std::from_chars`); Boost.JSON's `none` leaves no number text in its DOM, so it cannot.
yyjson writes a raw number verbatim, so `read (raw numbers) + write` is exact. sonic-cpp 1.0.2 has no parse flags,
and Glaze's generic DOM has no raw number mode (`validate_json` converts no number anyway). `(reused allocator)`:
yyjson's `yyjson_alc_dyn_new()`, RapidJSON's `MemoryPoolAllocator`s over user buffers for the values and the parse
stack; Boost.JSON's `parser (reused)` builds its value in a `monotonic_resource` over a buffer kept across calls. These
buffers grow after a call that needed more, so the timed calls do not allocate. `generic (double)` is `glz::generic`,
which stores every number as a double. The Glaze `(strict)` variants read with `validate_trailing_whitespace` (else
Glaze accepts anything after the value) and write with `escape_control_characters` (else Glaze writes a string's
control characters, e.g. U+0001, unescaped, which is not JSON; `gsoc-2018.json` has some).

| library | version | notes |
|---|---|---|
| `json_document`, `json` | this checkout | |
| yyjson | 0.13.0 | |
| simdjson | 5.1.1 | the single-header files of the tag |
| sonic-cpp | 1.0.2 | |
| RapidJSON | master 24b5e7a8b27f (2025-02-05) | |
| Glaze | 9.1.0 | `generic_u64` and `generic` (owning DOMs, member order kept) |
| Boost.JSON | 1.92.0 | monotonic resource |
| sonic-rs, simd-json, serde_json | see `rust/Cargo.lock` | serde_json with `float_roundtrip` |

SHA-256 of the downloads:

```
55f8a675397c505f9bee6c160e1c26b0085868f185d04d7a7727531fdbff4bd4  glaze-v9.1.0.tar.gz
30edf9e47c417f653546c39295fdb66ba5f89fb37eb3780122c6ee66605e5837  sonic-cpp v1.0.2.tar.gz
2d2601a82d2d3b7e143a3c8d43ef616671391034bc46891a9816b79cf2d3e7a8  rapidjson 24b5e7a8b27f42fa16b96fc70aade9106cf7102f.tar.gz
34e0f62a2bc11ab20d601e8ca1cc2b2079503aa45119a19133d89d19b94a0fae  yyjson 0.13.0.tar.gz
f3e5ee5f39051960b5ce65762ee4b6919caf270675eb52240ebd92f21a5bcefd  simdjson v5.1.1 singleheader/simdjson.h
3ea5f501cef6c2e16e28095b566feeb56021ca473aaf50aad32102f45d734195  simdjson v5.1.1 singleheader/simdjson.cpp
c4a3b310ddd2472416e091067166b0713be97c63f38c212c484ada022fd296ce  boost_1_92_0.tar.gz
```

### Timing

Every variant of a use case runs interleaved in every round, each timed call after an untimed one, and the best
round is reported (the method of `bench_view.cpp`). The order of the variants changes in every round (a shuffle with a
fixed seed; the first round keeps the listed order): on the Mac, a variant's time can depend on which variant ran
before it, by up to 15 %, and a fixed order would give each variant the same neighbour in every round. `jeopardy.json` (50 MB) gets a fifth of the rounds (at least 3,
at most the given number).

## Building and running

All libraries except yyjson and simdjson are used header-only. With the downloads unpacked into `DL`
(`compare.py --download` fetches yyjson and Boost into its build directory, and simdjson 4.6.11, so take simdjson
5.1.1's `singleheader` files from its tag):

```sh
cc  -O3 -DNDEBUG -c $DL/yyjson-0.13.0/src/yyjson.c -o yyjson.o
c++ -std=c++17 -O3 -DNDEBUG -c $DL/simdjson-5.1.1/singleheader/simdjson.cpp -o simdjson.o
c++ -std=c++23 -O3 -DNDEBUG -DRAPIDJSON_NEON \
    -I ../../../../include -I $DL/yyjson-0.13.0/src -I $DL/simdjson-5.1.1/singleheader -I $DL/boost_1_92_0 \
    -I $DL/glaze-9.1.0/include -I $DL/rapidjson/include -I $DL/sonic/include \
    bench_all.cpp yyjson.o simdjson.o -o bench_all
./bench_all <json_test_data> 30 > mac-cpp-1.log

cd rust && cargo build --release --locked && ./target/release/bench_rs <json_test_data> 30 > ../mac-rs-1.log

python3 summarize.py mac-cpp-*.log --rust mac-rs-*.log --json mac.json
```

With GCC 16 and Homebrew Clang on macOS, build the three steps with the same flags plus
`--sysroot=$(xcrun --show-sdk-path)` (`gcc-16`, `g++-16`) or `-isysroot $(xcrun --show-sdk-path)`
(`/opt/homebrew/opt/llvm/bin/clang`, `clang++`). The key selectors and simdjson's `tag_invoke` need C++20, so
`bench_all.cpp` needs `-std=c++20` or newer.

Both programs take `<json_test_data> [rounds] [file] [use case]`: `./bench_all <json_test_data> 30 canada edit` times
only the edit of `canada.json`; `""` stands for all files; the file names are `twitter`, `citm_catalog`, `canada`,
`jeopardy`, `status`, `twitter_min` and `citm_catalog_min`. The checks cover only the selected files and use cases.
bench_all uses `fork()` for the probes and the crash check (macOS, Linux).

`--files <dir> [rounds] [file] [use case]` runs `validate`, `sum`, `minify` and `write` (`select` and `edit` are
defined only for the files above) on every `*.json` file of a directory, named by their stem; files under 500 KB are
timed in batches of about 500 KB of input. It is meant for files the libraries were not tuned on, such as the
`jsonexamples` of [simdjson-data](https://github.com/simdjson/simdjson-data) without `twitter.json`,
`citm_catalog.json` and `canada.json`. `summarize.py` takes such logs as well.

On x86-64, use `-march=haswell -DRAPIDJSON_SSE42` instead of `-DRAPIDJSON_NEON` (sonic-cpp needs AVX2), pin the
process to one core, and time one file per process. Glaze 9 needs `std::expected`, which Clang 18 and older cannot
use from GCC 13's standard library (Clang 19 and newer can); `-DBENCH_NO_GLAZE=1` builds without it. For Rust, build
with `RUSTFLAGS="-C target-cpu=haswell"` to match `-march=haswell`.

## Reading the results

A log line holds the file, the use case, and one cell per variant: `| <library>: <variant> [<level>] <time>us
(<ratio>x)`, the ratio relative to the first variant of the line. `summarize.py` prints, for every use case and file,
(a) per library the best `full` variant and, if faster, the best variant at any level, with their ratios to the best
`full` `nlohmann json_document` variant (`(reused)` and `(reused allocator)` variants are never a library's best; a
`reused:` line below the library shows its best reused variant in the same way), (b) all variants with their levels
and times, and (c) what the variants below `full` accept, and the excluded variants. `--json` writes
`{use case: {file: {library: {"best": {"variant", "us", "level"} or null, "best_any": {...}, "best_reused": {...} or
null, "best_reused_any": {...} or null, "variants": {variant: {"us", "level"}}, "excluded": {...}}}}}` for the chart
scripts (`best_reused`: the best full reused variant; `best_reused_any`: at any level). Several logs are combined by taking each cell's best
time; a variant excluded for one file is left out for every file of that use case.
On a shared machine, differences of a few percent are noise: run twice and compare.
