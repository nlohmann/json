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
