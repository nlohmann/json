# Performance history

The benchmarks in [`tests/benchmarks`](../README.md) compare two versions. The program here answers a different
question: *which commit* made something faster or slower. `history.cpp` is one fixed benchmark that uses only API
3.12.0 already has. `history.py` compiles it against the `single_include` of every first-parent commit that changed
`json.hpp` or `json_view.hpp`, runs all of them interleaved, and writes one CSV row per commit with its pull request.
The timeline in the post [How 3.13.0 got faster](https://json.nlohmann.me/home/blog/how_3_13_0_got_faster/) comes from
it. It is not built by CMake or run by CI.

## Workloads

| name | what it does |
|---|---|
| `parse_twitter`, `parse_citm`, `parse_canada` | `json::parse()` of a `std::string` (`citm_catalog.json` as distributed is indented by four spaces) |
| `parse_citm_compact` | the same with a minified copy of `citm_catalog.json` |
| `parse_twitter_ifstream` | `json::parse()` of an `std::ifstream`, opening the file included |
| `accept_twitter` | `json::accept()` |
| `view_parse_*` | `json_document::parse()`; only where the header has `json_view.hpp` |
| `dump_twitter`, `dump_citm`, `dump_canada`, `dump4_citm` | `dump()` and `dump(4)` |
| `from_cbor_twitter`, `to_cbor_twitter` | read and write CBOR |
| `copy_destroy_citm` | copy a parsed document and destroy the copy |
| `equal_citm` | copy a parsed document and compare it with `==` |

Each workload runs in batches of at least 20 ms; the program prints the median of 9 batches in microseconds per call.

## Running it

```sh
mkdir -p ~/history/data
cp <json_test_data>/nativejson-benchmark/{twitter,citm_catalog,canada}.json ~/history/data/
python3 history.py build --repo ../../.. --work ~/history          # about 300 builds, a few minutes in parallel
caffeinate -i python3 history.py run --work ~/history --rounds 4    # about 1 h 45 min on an M1 Max (about 4 s per binary and round)
python3 history.py summarize --work ~/history > history.csv
```

`--extra DIR` adds one more header directory, such as an amalgamation of `develop` with open pull requests merged
in. `run` waits whenever the 1-minute load average is 4 or more.

## Reading the results

A single commit can move a workload by a few percent through code layout alone: the functions it did not touch
move to other addresses. Read a change as a step only if it is larger than that and stays. To check one, time the
two commits against each other with more rounds, or compare instruction counts.
