# json_document against other JSON libraries

[`compare.py`](../compare.py) compares `json_document` with yyjson, simdjson and Boost.JSON. The programs here add
sonic-cpp, RapidJSON and Glaze in C++, and sonic-rs, simd-json and serde_json in Rust, for the post
[How 3.13.0 got faster](https://json.nlohmann.me/home/blog/how_3_13_0_got_faster/#how-it-compares). They are not
built by CMake or run by CI.

## What is measured

The same files and method as `bench_view.cpp`: `twitter.json`, `citm_catalog.json`, `canada.json`, `jeopardy.json`
and one status object of `twitter.json`; every engine runs interleaved in every round, each timed call after an
untimed one, and the best round is reported.

| workload | what it does |
|---|---|
| `parse` | build the document and free it |
| `traverse` | parse, then visit every value, convert every number, touch every string and key |
| `select` | parse, then read a few fields of every record (the fields are listed in `bench_view.cpp`) |
| `parse+dump` | parse, then write the document as compact JSON |
| `dump` | write a document parsed beforehand as compact JSON; only the writing is timed |

Before timing, every engine must report the same number of values, the same number of string bytes, and a sum of all
numbers in document order that is bit-identical to `json_document`'s (`json::parse` visits objects in key order and
is compared within 1e-9): every number is converted exactly. For *select*, all engines must return the same value.
For *dump*, every engine's output must read back as the same values with the same sum, so every float is written
exactly.

| engine | version | notes |
|---|---|---|
| `json_document` | this checkout | `json_view (reused)`: one document whose `read()` reuses its memory |
| yyjson | 0.13.0 | |
| simdjson | 4.6.11 | DOM with a reused parser (as recommended) and a fresh one; On-Demand for *traverse* and *select* |
| sonic-cpp | 1.0.2 | |
| RapidJSON | master 24b5e7a8b27f (2025-02-05) | `kParseFullPrecisionFlag` (correctly rounded floats); also default flags and in situ parsing with a copy of the input |
| Glaze | 9.0.0 | `generic_u64` (owning DOM), `lazy_json` (no validation), and for *select* reading into structs that declare only the fields used |
| Boost.JSON | 1.92.0 (Mac), 1.83 (system, x86-64) | monotonic resource |
| sonic-rs, simd-json, serde_json | see `rust/Cargo.lock` | simd-json parses in place: its times include copying the input; serde_json with `float_roundtrip` |

SHA-256 of the downloads:

```
dd7b033c5bf6e4308615bb7834c541291d5b20f64121d9a68222a39414635517  glaze v9.0.0.tar.gz
30edf9e47c417f653546c39295fdb66ba5f89fb37eb3780122c6ee66605e5837  sonic-cpp v1.0.2.tar.gz
2d2601a82d2d3b7e143a3c8d43ef616671391034bc46891a9816b79cf2d3e7a8  rapidjson 24b5e7a8b27f42fa16b96fc70aade9106cf7102f.tar.gz
34e0f62a2bc11ab20d601e8ca1cc2b2079503aa45119a19133d89d19b94a0fae  yyjson 0.13.0.tar.gz
61d948fc24f0d793829ad658058e7597d064988a89b4607ea02e401a82df98ff  simdjson v4.6.11.tar.gz
c4a3b310ddd2472416e091067166b0713be97c63f38c212c484ada022fd296ce  boost_1_92_0.tar.gz
```

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

python3 summarize.py mac-cpp-*.log --rust mac-rs-*.log
```

On x86-64, use `-march=haswell -DRAPIDJSON_SSE42` instead of `-DRAPIDJSON_NEON` (sonic-cpp needs AVX2), pin the
process to one core, and add the document name as third argument to time one document per process. A fourth
argument times only one workload (`./bench_all <json_test_data> 30 "" dump`); `bench_rs` takes the workload as third
argument. Glaze 9 needs
`std::expected`, which Clang 18 cannot use from GCC 13's standard library; `-DBENCH_NO_GLAZE=1` builds without it.

## Reading the results

`summarize.py` prints, for every document and workload, the engines ordered by time and the fastest other engine
relative to `json_document`. Fresh documents are compared with fresh ones; the reused `json_document` is compared
with simdjson's reused parser. On a shared machine, differences of a few percent are noise: run twice and compare.
