# json_view compared with other libraries

The in-tree benchmarks in [`tests/benchmarks`](../README.md) measure `json_document` against `json::parse` only. The
programs here compare it with [yyjson](https://github.com/ibireme/yyjson),
[simdjson](https://github.com/simdjson/simdjson), and [Boost.JSON](https://github.com/boostorg/json): the question
users ask when they pick a library. They are not built by CMake or run by CI.

## Reproducing the numbers

`compare.py` builds the programs against `include/` of this checkout, runs them, and writes the results together with
everything needed to reproduce them to `results/<date>-<host>.md` (and `.csv`): the date, the commit, the CPU, the
OS, the compiler, the flags, and the versions of all libraries.

```sh
python3 tests/benchmarks/json_view/compare.py --data <json_test_data directory> [--native] [--rounds 30]
```

- `--data` is the downloaded [test data](https://github.com/nlohmann/json_test_data), e.g. the `test_files` directory
  of a CMake build directory. It needs `nativejson-benchmark/{twitter,citm_catalog,canada}.json` and
  `jeopardy/jeopardy.json`.
- The other libraries come from the system: pkg-config, or Homebrew (`brew install yyjson simdjson boost`). With
  `--download`, pinned releases are downloaded instead and checked against their SHA-256. Without Boost headers (or
  with `--no-boost`), the Boost.JSON columns are skipped, and the results say so.
- `--corpus file...` adds files to the corpus benchmark, e.g. those of
  [simdjson-data](https://github.com/simdjson/simdjson-data) or the
  [yyjson benchmark](https://github.com/ibireme/yyjson_benchmark).
- Only the Python 3 standard library is used; a C++17 compiler is needed (`CXX` and `CC` are honored).

For numbers worth publishing, use a quiet machine (see [Getting stable numbers](../README.md#getting-stable-numbers)),
the default 30 rounds or more, and `--native` only if the other libraries were built for the same CPU.

### On GitHub-hosted runners

The workflow [json_view benchmarks](../../../.github/workflows/json_view_benchmarks.yml) runs `compare.py --download`
on demand: by hand (Actions → "json_view benchmarks" → "Run workflow"), on an x86-64 or AArch64 Ubuntu runner with GCC
or Clang, or when a pull request gets the label `benchmark`, on both architectures with GCC. The results appear as the
job summary and as an artifact. Shared runners are noisy, so these numbers show
where `json_view` stands on another architecture; they are not meant for publication.

## What is measured

`bench_view.cpp` runs four workloads on twitter, citm_catalog, canada, jeopardy, a single tweet (`status`), and a
JSON-RPC request (`rpc`):

| workload | what it does |
|---|---|
| parse | build and free a document |
| traverse | parse, then visit every value, convert every number, touch every string and key |
| select | parse, then read a few fields per record (e.g. id, user name, and retweet count of each tweet) |
| dump | serialize a parsed document (compact) |

`bench_corpus.cpp` runs parse, traverse, and dump on any list of files, so that no library is tuned to a handful of
documents. Its dump also writes the numbers as they are in the input: `json_view` with `number_format::source`, and
yyjson with numbers read as raw text (`YYJSON_READ_NUMBER_AS_RAW`), without converting them.

`bench_edit.cpp` measures read-modify-write: parse, apply the same logical edits with each library's own API, and
serialize (compact). Workloads: `patch` (a handful of edits at fixed places) and `update` (edits in every record).
An editable `json_document` edits in place; yyjson copies its immutable document into a mutable one first
(`yyjson_doc_mut_copy`); Boost.JSON and `json::parse` build mutable DOMs; simdjson cannot edit a document. All
outputs are checked to describe the same value.

Before anything is timed, all engines must accept each document and agree on the traversal: the number of values, the
bytes of all strings and keys, and the sum of all numbers. All engines run interleaved in every round, and the best
round is reported, as time and as a factor of the `json_view` time (below 1 means faster than `json_view`). Each timed
call follows an untimed call of the same engine: otherwise the engine after `json::parse` pays for the allocator
cleaning up the tens of thousands of nodes `json::parse` just freed (with glibc, this made `json_view` look 1.7 times
slower on citm_catalog traverse).

The engines do not all offer the same features, which the numbers should be read with:

| engine | document | random access | editable | notes |
|---|---|---|---|---|
| `json_view` | immutable index into the text | yes | no | a fresh document per parse; "reused" parses into the same document |
| yyjson | immutable (`yyjson_read`) | yes | via a mutable copy | |
| simdjson DOM | immutable, parser reused | yes | no | "fresh" uses a new parser per parse |
| simdjson On-Demand | none: forward-only, lazy | no | no | only traverse and select |
| Boost.JSON | owning, mutable DOM | yes | yes | monotonic resource |
| `json::parse` | owning, mutable DOM | yes | yes | |

Reusing memory matters as much as the parser. simdjson DOM reuses its parser, so it writes into memory it already
touched; a fresh `json_view` document or yyjson document gets new memory for every parse. On Linux, glibc returns large
blocks to the system when they are freed, so every fresh parse of a large document pays a page fault per 4 KiB page:
on x86-64 Linux, a fresh `json_view` parse of jeopardy took about twice as long as a reused one. On macOS on Apple
silicon, with 16 KiB pages, the difference is much smaller. Compare "json_view (reused)" with "simdjson DOM", and the
fresh `json_view` with "simdjson DOM (fresh)" and yyjson.

## Published results

Results are only published with the file `compare.py` wrote, which names the machine and the versions; see
`results/`. Numbers from one machine and compiler do not carry over to another: rerun the script.
