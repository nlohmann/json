# Benchmarks

Micro-benchmarks for parsing, serialization and the binary formats, written with
[Google Benchmark](https://github.com/google/benchmark). They are not run by CI; see
[When to run them](#when-to-run-them).

## What is measured

| benchmark | what it does |
|---|---|
| `ParseFile`, `ParseString` | parse JSON from a file stream or a string |
| `ParseIndented` | parse the large files re-indented by 4 spaces, for the lexer's whitespace handling |
| `Dump` | serialize, compact (`-`) and indented (`4`) |
| `ToCbor`, `BinaryToCbor` | write CBOR; `BinaryToCbor` writes binary values of growing size |
| `FromMsgpack` | read MessagePack; unchanged over the years, so its numbers stay comparable across releases |
| `FromBinaryBuffer`, `FromBinaryFile` | read CBOR, MessagePack, UBJSON, BJData and BSON from a buffer or a `FILE*` |
| `FromBinaryShape` | read deeply nested, container-heavy and scalar-heavy documents in every binary format |
| `FromCborChunkedString` | read CBOR strings split into indefinite-length chunks |

The input files are those of [nativejson-benchmark](https://github.com/miloyip/nativejson-benchmark) (`canada`,
`citm_catalog`, `twitter`), a large `jeopardy` file, and number-heavy files (`floats`, `signed_ints`, ...).
`bytes_per_second` counts the bytes read or written: the JSON text when parsing, the output when serializing.

## Requirements

- CMake 3.11 or later, a C++11 compiler, and Ninja for the `make` target.
- Network access on the first configure: CMake fetches Google Benchmark and downloads the
  [test data](https://github.com/nlohmann/json_test_data) into the build directory. To reuse a download, pass
  `-DJSON_TestDataDirectory=<build directory>/test_files`.
- The benchmarks include `single_include/nlohmann/json.hpp`, so run `make amalgamate` after changing anything in
  `include/`.

GCC and Clang builds use `-O3 -flto -DNDEBUG`.

## Running them

From the repository root, this builds everything from scratch in `cmake-build-benchmarks` and runs all benchmarks:

```sh
make run_benchmarks
```

To build once and run selectively:

```sh
cmake -S tests/benchmarks -B build-benchmarks -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-benchmarks
build-benchmarks/json_benchmarks --benchmark_filter='ParseString|Dump'
```

Useful options of `json_benchmarks`:

| option | effect |
|---|---|
| `--benchmark_list_tests` | list the benchmarks instead of running them |
| `--benchmark_filter=<regex>` | run only the benchmarks whose names match |
| `--benchmark_repetitions=<n>` | run every benchmark `n` times and add mean, median, standard deviation and coefficient of variation |
| `--benchmark_enable_random_interleaving=true` | run the repetitions in random order, which spreads out drifts such as thermal throttling |
| `--benchmark_min_time=<seconds>s` | run each benchmark at least this long (e.g. `2s`) |
| `--benchmark_out=<file> --benchmark_out_format=json` | also write the results to a file, e.g. for `compare.py` |

## Reading the output

Each line shows the wall-clock `Time` and the `CPU` time per iteration, the number of `Iterations` Google Benchmark
chose, and the throughput in `bytes_per_second`. With repetitions, the lines ending in `_median` are the ones to
compare. A `_cv` (coefficient of variation) above a few percent means the machine was too noisy for small
differences to mean anything.

## Comparing two versions

To see what a change or a release did, build the same benchmarks twice: once against the header of the version to
compare with, and once against the current one. `JSON_BENCHMARK_INCLUDE_DIR` names the directory holding the
`nlohmann/json.hpp` to benchmark. For example, to compare the current checkout with 3.12.0:

```sh
# the header of the version to compare with
mkdir -p build-baseline-header/nlohmann
git show v3.12.0:single_include/nlohmann/json.hpp > build-baseline-header/nlohmann/json.hpp

# the same benchmarks, built against either header
cmake -S tests/benchmarks -B build-baseline -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DJSON_BENCHMARK_INCLUDE_DIR="$PWD/build-baseline-header"
cmake -S tests/benchmarks -B build-current -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-baseline
cmake --build build-current

# run both, back to back
build-baseline/json_benchmarks --benchmark_repetitions=10 --benchmark_enable_random_interleaving=true \
                               --benchmark_out=build-baseline/results.json --benchmark_out_format=json
build-current/json_benchmarks --benchmark_repetitions=10 --benchmark_enable_random_interleaving=true \
                              --benchmark_out=build-current/results.json --benchmark_out_format=json
```

Google Benchmark ships a tool to compare the two result files. It needs NumPy and SciPy:

```sh
python3 -m venv build-venv
build-venv/bin/pip install numpy scipy
build-venv/bin/python build-current/_deps/benchmark-src/tools/compare.py -a benchmarks build-baseline/results.json build-current/results.json
```

The tool's own `tools/requirements.txt` pins the newest NumPy and SciPy, which may need a newer Python than yours;
unpinned versions work as well. In its output:

- the `Time` and `CPU` columns are relative changes: `-0.35` means 35% faster, `+0.10` means 10% slower;
- `_pvalue` lines report a Mann-Whitney U test of whether the two versions differ. It needs at least 9
  repetitions, and a p-value below 0.05 means the difference is unlikely to be noise;
- `OVERALL_GEOMEAN` summarizes all benchmarks;
- `-a` shows only the aggregates, not every repetition.

The header you compare with must support everything the benchmarks use. The current benchmarks build against 3.12.0.
Only benchmarks present in both result files are compared, so for older releases, either filter the benchmarks or
build that release's own `tests/benchmarks` against its own header.

## Getting stable numbers

- Build and run both versions on the same machine, one right after the other.
- Keep the machine otherwise idle: no builds, no browser, and a laptop plugged in.
- On Linux, set the CPU frequency governor to `performance`, e.g. `sudo cpupower frequency-set --governor performance`.
  Google Benchmark prints a warning when frequency scaling is enabled. Pinning the process to a core
  (`taskset -c 2 ...`) helps as well.
- Use 10 or more repetitions with random interleaving, compare medians, and treat changes within the `_cv` as noise.

## When to run them

They are a manual step, not part of CI: shared CI runners vary more between runs than most of the effects measured.
Run the comparison above before a release, comparing the previous release tag with `develop`, and for pull requests
that claim to change performance.
