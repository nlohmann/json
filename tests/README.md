# Unit tests

The unit tests are in [`src/unit-*.cpp`](src) and use [doctest](https://github.com/doctest/doctest). Each file becomes
one CTest test per C++ standard it is built for, named after the file: `src/unit-foo.cpp` becomes `test-foo_cpp11`.

## Build and run

```sh
cmake -S . -B build -DJSON_BuildTests=ON
cmake --build build -j 10
ctest --test-dir build -j 10
```

The [CMake options](../docs/mkdocs/docs/integration/cmake.md) starting with `JSON_Test` (and `JSON_FastTests`,
`JSON_Valgrind`) control the test build. The most relevant ones:

- `JSON_TestStandards`: build every test file for the given standards, e.g., `-DJSON_TestStandards=17`. By default,
  a file is built for C++11 and for each standard whose `JSON_HAS_CPP_<N>` macro it mentions (see below).
- `JSON_TestUnityBuild`: compile several test files together (see below). Set it to `OFF` to get one executable per
  test file, e.g., to debug a single test in a debugger.
- `JSON_TestShard`: build only a part of the test files, e.g., `-DJSON_TestShard=0/2`.

To run the tests of one file only, run its CTest test, e.g., `ctest --test-dir build -R test-foo_cpp11`.

## How test files are built

Two mechanisms keep the compile time down. Both are automatic, but they set a few rules for test files.

### C++ standards

A test file is built for a C++ standard beyond C++11 if its text contains `JSON_HAS_CPP_<N>`, for instance in
`#ifdef JSON_HAS_CPP_17`, or in a comment `// JSON_HAS_CPP_17` next to code that needs a macro only defined for that
standard, such as `JSON_HAS_FILESYSTEM`. Then the *whole file* is compiled again for that standard.

So that this does not happen for the large files, tests that need C++14, C++17, or C++20 go into a separate file
`src/unit-<name>-cpp<N>.cpp` (e.g., [`src/unit-regression3-cpp17.cpp`](src/unit-regression3-cpp17.cpp)), whose body
is wrapped in `#ifdef JSON_HAS_CPP_<N>`. The main file `src/unit-<name>.cpp` must not mention `JSON_HAS_CPP_<N>` at
all, not even in a comment, so it is built for C++11 only. The CI jobs `ci_test_*_cxx<N>` still build every test file
for every standard.

### Unity build

With `JSON_TestUnityBuild` (`ON` by default, `OFF` with MinGW), CMake compiles several test files as one translation
unit, so they share the template instantiations of the library. CMake generates `build/tests/unity/test-unity-*.cpp`,
which `#include` the test files of a batch. Every test file still gets its own CTest test, which runs the batch
executable with `--source-file=*unit-foo.cpp`, so only the test cases of that file run.

CMake decides from the macros a file defines *before* including `<nlohmann/json.hpp>`:

| Macros defined before the include                                                         | Built as                          |
|-------------------------------------------------------------------------------------------|-----------------------------------|
| none (or only `SKIP_TESTS_FOR_*` and similar macros derived from global definitions)      | batch with the other plain files  |
| only `JSON_TESTS_PRIVATE`                                                                 | batch with the other such files   |
| any library configuration macro (`JSON_DIAGNOSTICS`, `JSON_NO_IO`, `JSON_ASSERT`, ...)    | its own executable                |

Files with test-specific build options (`json_test_set_test_options(test-foo ...)` in
[`CMakeLists.txt`](CMakeLists.txt)) also get their own executable. The batchable files are split alphabetically into
batches of `JSON_TestUnityBatchSize` files, except for explicit groups of related files: `json_test_unity_group_binary`
compiles all binary-format tests together, because they share the binary readers and writers. Only add a group if it
measurably pays off; files that share little just make one slow translation unit.

## Rules for test files

Because the files of a batch share one translation unit, a test file must not affect the files that follow it:

1. **Give file-scope helpers file-specific names.** An anonymous namespace does not help, as the batch is one
   translation unit. Use a name such as `my_allocator_2982`, or wrap the helpers in a namespace named after the file
   (e.g., `namespace unit_comparison_detail`). Clashes show up as compile errors.
2. **Do not `#undef` library macros**, such as `JSON_HAS_CPP_17`, at the end of a file: this silently disables the tests
   that depend on them in the later files of the batch. `#undef` macros you define yourself after including the library.
3. **Put version-dependent tests into `unit-<name>-cpp<N>.cpp`** (see [C++ standards](#c-standards)).
4. **Define test cases in the `.cpp` file itself.** The batch executable selects the tests of a file by its name, so a
   `TEST_CASE` in a shared header is not run. The only exception is the test case in
   [`src/make_test_data_available.hpp`](src/make_test_data_available.hpp), which CMake handles explicitly.

To check a new file for clashes with all others at once, build with `-DJSON_TestUnityBatchSize=1000`, which puts all
batchable files of a kind into one translation unit.

## Where to add tests

Tests are structured along the features of the library. Usually, an existing file is the right place:

- For a bug fix, add a section referencing the issue to [`src/unit-regression3.cpp`](src/unit-regression3.cpp), or to
  [`src/unit-regression3-cpp17.cpp`](src/unit-regression3-cpp17.cpp) /
  [`src/unit-regression3-cpp20.cpp`](src/unit-regression3-cpp20.cpp) if the test needs C++17 / C++20.
  [`src/unit-regression2.cpp`](src/unit-regression2.cpp) holds older tests and should not grow further.
- When testing exceptions, use `CHECK_THROWS_WITH_AS`, which also checks the `what()` message.

A new file `src/unit-<name>.cpp` is picked up automatically when CMake runs again; no change to `CMakeLists.txt` is
needed.

See also [`fuzzing.md`](fuzzing.md) for fuzz testing.
