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

The files are `twitter.json`, `citm_catalog.json`, `canada.json` (nativejson-benchmark), `jeopardy.json`, and the first
status of `twitter.json` (written by `json::dump()`, timed in batches of 200).

### Input contract

The input is a `const std::string` holding the file, with at least 64 bytes of spare capacity (`reserve`), so libraries
that need padding (simdjson) can use it without a copy. A variant that modifies the input (in-situ parsing: yyjson
`YYJSON_READ_INSITU`, RapidJSON `ParseInsitu`, simd-json) copies it inside the timed call; its name says `(copy)`.
Each timed call starts from the text and frees everything it built, except variants named `(reused)`, which keep a
parser or document across calls (simdjson's reused parsers, `json_document::read()`, simd-json's buffers). These are
reported but never chosen as a library's best. In Rust, the input is the file as bytes (`&[u8]`), so every library
has to validate UTF-8 itself.

### Correctness rules

Before timing, every variant runs on the file and must produce the right result:

- `validate`: `true`.
- `sum`: the same number of values, the same number of string and key bytes, and a sum of all numbers that is
  bit-identical to `json_document`'s (document order), so every number is converted exactly; variants that visit
  objects in another order (`nlohmann json: parse`, simd-json and serde_json values) are compared within 1e-9.
- `select`: the same value as `json_document`.
- `edit`, `minify`, `write`: the output, read with `json::parse`, compares equal (`==`) to the expected document (for
  `edit`, the edit applied to a `json` value; floats compare exactly, so every float must be written exactly). In
  Rust, `serde_json::Value` (with `float_roundtrip`) is the reference.

A variant that gives a wrong result on a file, or crashes on it, is printed as
`excluded: <file> <use case> | <variant> | <reason>` and not timed.

### Validation levels

Except for `write`, every variant is also probed with three malformed inputs derived from each file: the file
truncated by one byte (after trailing whitespace), a stray `,` before the first `}`, and a `0xFF` byte inside a string
value (the first in the second half of the file, or the last one; never a key, so that a variant that accepts the byte
still finds the keys it looks up). The probes run in a child process, so a crash is caught. The result is the
variant's *validation level*, printed in its cell (`sonic-cpp: Document [no UTF-8] 380.1us`):

| level | meaning |
|---|---|
| `full` | rejects all three probes |
| `no UTF-8` | rejects the truncated input and the stray comma, accepts the `0xFF` byte |
| `partial` | accepts the truncated input or the stray comma, or crashes on any probe |
| `n/a` | `write`: there is no input to validate (counts as `full`) |

What a variant accepts is printed as `level: <file> <use case> | <variant> | <level> | <what>`. A variant's level in
the summary is the worst it got for any file. UTF-8 validation is enabled where a library has a switch (RapidJSON
`kParseValidateEncodingFlag`; the `(no encoding check)` variants leave it off). sonic-cpp 1.0.2 cannot validate
UTF-8 at all; serde_json does not validate UTF-8 in the parts it skips (`IgnoredAny`, unknown struct fields) unless
the input is checked with `std::str::from_utf8` first (the `from_utf8 + ...` variants).

The sum and select reference values are printed as `check ... reference:` lines; `summarize.py` warns if the C++ and
Rust logs disagree.

### Variants

Level on the Mac in brackets where it is not `full` (`P` = partial, `U` = no UTF-8); every `write` variant is `n/a`.

| library | validate | sum | select | edit | minify | write |
|---|---|---|---|---|---|---|
| nlohmann json_document | `accept`, `parse`, `read (reused)` | `parse`, `read (reused)` | `parse`, `structs (from_json)`, `read (reused)` | `editable`, `editable (source numbers)` (`json_editable_document`: set/erase, `dump` with `number_format::source`) | `parse + dump`, `parse + dump (source numbers)`, `read + dump (reused)` | `dump`, `dump (source numbers)` |
| nlohmann json | `accept`, `parse` | `parse`, `sax` | `parse`, `structs (from_json)` | `parse`, `ordered_json` | `parse + dump` | `dump` |
| yyjson | `read`, `insitu (copy)` | `read`, `insitu (copy)` | `read`, `insitu (copy)` | `mut copy`, `insitu (copy) + mut copy` (`yyjson_doc_mut_copy`) | `read + write`, `insitu (copy) + write` | `write` |
| simdjson | `DOM`, `DOM (reused)` | `DOM`, `DOM (reused)`, `On-Demand`, `On-Demand (reused)` | `DOM`, `DOM (reused)`, `On-Demand` [P], `On-Demand (reused)` [P] | n/a (no mutable document) | `DOM + to_string`, `DOM (reused) + to_string`, `minify` [P] | `to_string` |
| RapidJSON | `SAX` (null handler), `Document`, `insitu (copy)` | `Document`, `SAX`, `insitu (copy)` | `Document`, `insitu (copy)` | `Document`, `insitu (copy)` | `Document + Writer`, `SAX to Writer`, `SAX to Writer (raw numbers)` | `Writer` |
| RapidJSON, `(no encoding check)` | the same [U] | the same [U] | the same [U] | the same [U] | the same [U] | |
| sonic-cpp | `Document` [U] | `Document` [U] | `Document` [U] | `Document` [U] | `Document + Serialize` [U] | `Serialize` |
| Glaze | `validate_json`, `generic` | `generic`, `lazy_json` [P] | `structs` [P], `structs (validate_skipped)`, `generic`, `lazy_json` [P] | `generic` | `generic`, `minify_json` [P] | `generic` |
| Boost.JSON | `SAX` (`basic_parser`), `parse` | `parse`, `SAX` | `parse` | `parse` | `parse + serialize` | `serialize` |
| serde_json | `IgnoredAny` [U], `from_utf8 + IgnoredAny`, `Value` | `visitor`, `Value` | `structs` [U], `from_utf8 + structs`, `Value` | `Value` | `Value` | `Value` |
| sonic-rs | `IgnoredAny`, `Value` | `visitor`, `Value` | `structs`, `Value` | `Value` | `Value` | `Value` |
| simd-json | `tape (copy)`, `borrowed (copy)`, `tape (reused)` | `visitor (copy)`, `borrowed (copy)`, `borrowed (reused)` | `structs (copy)`, `borrowed (copy)` | `owned (copy)`, `borrowed (copy)` | `borrowed (copy)` | `borrowed` |

`structs` read into types that declare only the fields `select` uses (Glaze with `error_on_unknown_keys = false`,
and with `validate_skipped` to validate what it skips; serde derive; nlohmann/json's `from_json()` of the
`NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE` macro, from a `json` value or from a `json_document`'s view); `visitor` is a serde `DeserializeSeed` that sums without building a value; `SAX` and `sax` are the
libraries' event interfaces with a summing (or, for `validate`, an empty) handler. RapidJSON parses with
`kParseFullPrecisionFlag` (correctly rounded floats; without it, sums and written floats are wrong) and Boost.JSON with
`number_precision::precise`, as every other library rounds correctly by default.

| library | version | notes |
|---|---|---|
| `json_document`, `json` | this checkout | |
| yyjson | 0.13.0 | |
| simdjson | 4.6.11 | |
| sonic-cpp | 1.0.2 | |
| RapidJSON | master 24b5e7a8b27f (2025-02-05) | |
| Glaze | 9.0.0 | `generic_u64` (owning DOM, member order kept) |
| Boost.JSON | 1.92.0 | monotonic resource |
| sonic-rs, simd-json, serde_json | see `rust/Cargo.lock` | serde_json with `float_roundtrip` |

SHA-256 of the downloads:

```
dd7b033c5bf6e4308615bb7834c541291d5b20f64121d9a68222a39414635517  glaze v9.0.0.tar.gz
30edf9e47c417f653546c39295fdb66ba5f89fb37eb3780122c6ee66605e5837  sonic-cpp v1.0.2.tar.gz
2d2601a82d2d3b7e143a3c8d43ef616671391034bc46891a9816b79cf2d3e7a8  rapidjson 24b5e7a8b27f42fa16b96fc70aade9106cf7102f.tar.gz
34e0f62a2bc11ab20d601e8ca1cc2b2079503aa45119a19133d89d19b94a0fae  yyjson 0.13.0.tar.gz
61d948fc24f0d793829ad658058e7597d064988a89b4607ea02e401a82df98ff  simdjson v4.6.11.tar.gz
c4a3b310ddd2472416e091067166b0713be97c63f38c212c484ada022fd296ce  boost_1_92_0.tar.gz
```

### Timing

Every variant of a use case runs interleaved in every round, each timed call after an untimed one, and the best
round is reported (the method of `bench_view.cpp`). `jeopardy.json` (50 MB) gets a fifth of the rounds (at least 3,
at most the given number).

## Building and running

All libraries except yyjson and simdjson are used header-only. With the downloads unpacked into `DL`
(`compare.py --download` fetches yyjson, simdjson and Boost into its build directory):

```sh
cc  -O3 -DNDEBUG -c $DL/yyjson-0.13.0/src/yyjson.c -o yyjson.o
c++ -std=c++17 -O3 -DNDEBUG -c $DL/simdjson-4.6.11/singleheader/simdjson.cpp -o simdjson.o
c++ -std=c++23 -O3 -DNDEBUG -DRAPIDJSON_NEON \
    -I ../../../../include -I $DL/yyjson-0.13.0/src -I $DL/simdjson-4.6.11/singleheader -I $DL/boost_1_92_0 \
    -I $DL/glaze/include -I $DL/rapidjson/include -I $DL/sonic/include \
    bench_all.cpp yyjson.o simdjson.o -o bench_all
./bench_all <json_test_data> 30 > mac-cpp-1.log

cd rust && cargo build --release && ./target/release/bench_rs <json_test_data> 30 > ../mac-rs-1.log

python3 summarize.py mac-cpp-*.log --rust mac-rs-*.log --json mac.json
```

Both programs take `<json_test_data> [rounds] [file] [use case]`: `./bench_all <json_test_data> 30 canada edit` times
only the edit of `canada.json`; `""` stands for all files. The checks cover only the selected files and use cases.
bench_all uses `fork()` for the probes and the crash check (macOS, Linux).

On x86-64, use `-march=haswell -DRAPIDJSON_SSE42` instead of `-DRAPIDJSON_NEON` (sonic-cpp needs AVX2), pin the
process to one core, and time one file per process. Glaze 9 needs `std::expected`, which Clang 18 and older cannot
use from GCC 13's standard library (Clang 19 and newer can); `-DBENCH_NO_GLAZE=1` builds without it. For Rust, build
with `RUSTFLAGS="-C target-cpu=haswell"` to match `-march=haswell`.

## Reading the results

A log line holds the file, the use case, and one cell per variant: `| <library>: <variant> [<level>] <time>us
(<ratio>x)`, the ratio relative to the first variant of the line. `summarize.py` prints, for every use case and file,
(a) per library the best `full` variant and, if faster, the best variant at any level, with their ratios to the best
`full` `nlohmann json_document` variant (`(reused)` variants are never a library's best), (b) all variants with their
levels and times, and (c) what the variants below `full` accept, and the excluded variants. `--json` writes
`{use case: {file: {library: {"best": {"variant", "us", "level"} or null, "best_any": {...}, "variants": {variant:
{"us", "level"}}, "excluded": {...}}}}}` for the chart scripts. Several logs are combined by taking each cell's best
time; a variant excluded for one file is left out for every file of that use case.
On a shared machine, differences of a few percent are noise: run twice and compare.
