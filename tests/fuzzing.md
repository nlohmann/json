# Fuzz testing

Each parser of the library (JSON, BJData, BSON, CBOR, MessagePack, and UBJSON) can be fuzz tested. Currently,
[libFuzzer](https://llvm.org/docs/LibFuzzer.html) and [afl++](https://github.com/AFLplusplus/AFLplusplus) are supported.

## Corpus creation

For most effective fuzzing, a [corpus](https://llvm.org/docs/LibFuzzer.html#corpus) should be provided. A corpus is a
directory with some simple input files that cover several features of the parser and is hence a good starting point
for mutations.

```shell
TEST_DATA_VERSION=3.1.0
wget https://github.com/nlohmann/json_test_data/archive/refs/tags/v$TEST_DATA_VERSION.zip
unzip v$TEST_DATA_VERSION.zip
rm v$TEST_DATA_VERSION.zip
for FORMAT in json bjdata bson cbor msgpack ubjson
do
  rm -fr corpus_$FORMAT
  mkdir corpus_$FORMAT
  find json_test_data-$TEST_DATA_VERSION -size -5k -name "*.$FORMAT" -exec cp "{}" "corpus_$FORMAT" \;
done
rm -fr json_test_data-$TEST_DATA_VERSION
```

The generated corpus can be used with both libFuzzer and afl++. The remainder of this documentation assumes the corpus
directories have been created in the `tests` directory.

## libFuzzer

To use libFuzzer, you need to pass `-fsanitize=fuzzer` as `FUZZER_ENGINE`. In the `tests` directory, call

```shell
make fuzzers FUZZER_ENGINE="-fsanitize=fuzzer"
```

This creates a fuzz tester binary for each parser that supports these
[command line options](https://llvm.org/docs/LibFuzzer.html#options).

In case your default compiler is not a Clang compiler that includes libFuzzer (Clang 6.0 or later), you need to set the
`CXX` variable accordingly. Note the compiler provided by Xcode (AppleClang) does not contain libFuzzer. Please install
Clang via Homebrew calling `brew install llvm` and add `CXX=$(brew --prefix llvm)/bin/clang` to the `make` call:

```shell
make fuzzers FUZZER_ENGINE="-fsanitize=fuzzer" CXX=$(brew --prefix llvm)/bin/clang
```

Then pass the corpus directory as command-line argument (assuming it is located in `tests`):

```shell
./parse_cbor_fuzzer corpus_cbor
```

The fuzzer should be able to run indefinitely without crashing. In case of a crash, the tested input is dumped into
a file starting with `crash-`.

## afl++

To use afl++, you need to pass `-fsanitize=fuzzer` as `FUZZER_ENGINE`. It will be replaced by a `libAFLDriver.a` to
re-use the same code written for libFuzzer with afl++. Furthermore, set `afl-clang-fast++` as compiler.

```shell
CXX=afl-clang-fast++ make fuzzers FUZZER_ENGINE="-fsanitize=fuzzer" 
```

Then the fuzzer is called like this in the `tests` directory:

```shell
afl-fuzz -i corpus_cbor -o out  -- ./parse_cbor_fuzzer 
```

The fuzzer should be able to run indefinitely without crashing. In case of a crash, the tested input is written to the
directory `out`.

## OSS-Fuzz

The library is further fuzz-tested 24/7 by Google's [OSS-Fuzz project](https://github.com/google/oss-fuzz). It uses
the same `fuzzers` target as above and also relies on the `FUZZER_ENGINE` variable. See the used
[build script](https://github.com/google/oss-fuzz/blob/master/projects/json/build.sh) for more information.

In case the build at OSS-Fuzz fails, an issue will be created automatically.

### Handling OSS-Fuzz reports

OSS-Fuzz files the crashes it finds in its own [issue tracker](https://issues.oss-fuzz.com), not on GitHub. So that
each report can be traced to the change that fixed it, and each fix to the report it answers, fixes follow these
conventions:

- **Reference the OSS-Fuzz issue in the pull request**, next to any GitHub issue it closes, as `OSS-Fuzz: <id>` (for
  example, `OSS-Fuzz: 563659413`), and in the commit message. The ID alone does not disclose the crash. If the report
  was triaged into a GitHub issue, link the OSS-Fuzz issue there too.
- **Turn the reproducer into a unit test.** Download the testcase from the OSS-Fuzz report, reduce it if possible, and
  add it as a regression test to the unit test of the affected format (e.g., `tests/src/unit-bjdata.cpp`), with a
  comment naming the OSS-Fuzz issue. This way the input is checked by every CI run rather than only by OSS-Fuzz, and
  it stays covered even if OSS-Fuzz later closes the report as not reproducible.
- **Keep the fuzzer drivers and the unit tests in sync.** The round-trip checks of the UBJSON and BJData drivers are
  also run on a fixed corpus in the unit tests (see `tests/src/round_trip_corpus.hpp` and the "round-trip invariants"
  test cases), so a regression shows up in CI first. When a driver's checks change, change the unit tests with them.
- **Record in the report whether the bug shipped.** OSS-Fuzz asks whether a crash was a short-lived regression or
  affects a released version; answer it when the fix is merged, as it decides whether the fix needs a release note or
  a security advisory (see the [security policy](../.github/SECURITY.md)).

After the fix is merged, OSS-Fuzz re-runs the reproducer on its next build and marks the report as verified and
closed. If it does not, the fix is incomplete.
