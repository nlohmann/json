# Benchmark

[![Build Status](https://travis-ci.org/google/benchmark.svg?branch=master)](https://travis-ci.org/google/benchmark)
[![Build status](https://ci.appveyor.com/api/projects/status/u0qsyp7t1tk7cpxs/branch/master?svg=true)](https://ci.appveyor.com/project/google/benchmark/branch/master)
[![Coverage Status](https://coveralls.io/repos/google/benchmark/badge.svg)](https://coveralls.io/r/google/benchmark)
[![slackin](https://slackin-iqtfqnpzxd.now.sh/badge.svg)](https://slackin-iqtfqnpzxd.now.sh/)

A library to benchmark code snippets, similar to unit tests. Example:

```c++
#include <benchmark/benchmark.h>

static void BM_SomeFunction(benchmark::State& state) {
  // Perform setup here
  for (auto _ : state) {
    // This code gets timed
    SomeFunction();
  }
}
// Register the function as a benchmark
BENCHMARK(BM_SomeFunction);
// Run the benchmark
BENCHMARK_MAIN();
```

To get started, see [Requirements](#requirements) and
[Installation](#installation). See [Usage](#usage) for a full example and the
[User Guide](#user-guide) for a more comprehensive feature overview.

It may also help to read the [Google Test documentation](https://github.com/google/googletest/blob/master/googletest/docs/primer.md)
as some of the structural aspects of the APIs are similar.

### Resources

[Discussion group](https://groups.google.com/d/forum/benchmark-discuss)

IRC channel: [freenode](https://freenode.net) #googlebenchmark

[Additional Tooling Documentation](docs/tools.md)

[Assembly Testing Documentation](docs/AssemblyTests.md)

## Requirements

The library can be used with C++03. However, it requires C++11 to build,
including compiler and standard library support.

The following minimum versions are required to build the library:

* GCC 4.8
* Clang 3.4
* Visual Studio 14 2015
* Intel 2015 Update 1

See [Platform-Specific Build Instructions](#platform-specific-build-instructions).

## Installation

This describes the installation process using cmake. As pre-requisites, you'll
need git and cmake installed.

_See [dependencies.md](dependencies.md) for more details regarding supported
versions of build tools._

```bash
# Check out the library.
$ git clone https://github.com/google/benchmark.git
# Benchmark requires Google Test as a dependency. Add the source tree as a subdirectory.
$ git clone https://github.com/google/googletest.git benchmark/googletest
# Go to the library root directory
$ cd benchmark
# Make a build directory to place the build output.
$ cmake -E make_directory "build"
# Generate build system files with cmake.
$ cmake -E chdir "build" cmake -DCMAKE_BUILD_TYPE=Release ../
# or, starting with CMake 3.13, use a simpler form:
# cmake -DCMAKE_BUILD_TYPE=Release -S . -B "build"
# Build the library.
$ cmake --build "build" --config Release
```
This builds the `benchmark` and `benchmark_main` libraries and tests.
On a unix system, the build directory should now look something like this:

```
/benchmark
  /build
    /src
      /libbenchmark.a
      /libbenchmark_main.a
    /test
      ...
```

Next, you can run the tests to check the build.

```bash
$ cmake -E chdir "build" ctest --build-config Release
```

If you want to install the library globally, also run:

```
sudo cmake --build "build" --config Release --target install
```

Note that Google Benchmark requires Google Test to build and run the tests. This
dependency can be provided two ways:

* Checkout the Google Test sources into `benchmark/googletest` as above.
* Otherwise, if `-DBENCHMARK_DOWNLOAD_DEPENDENCIES=ON` is specified during
  configuration, the library will automatically download and build any required
  dependencies.

If you do not wish to build and run the tests, add `-DBENCHMARK_ENABLE_GTEST_TESTS=OFF`
to `CMAKE_ARGS`.

### Debug vs Release

By default, benchmark builds as a debug library. You will see a warning in the
output when this is the case. To build it as a release library instead, add
`-DCMAKE_BUILD_TYPE=Release` when generating the build system files, as shown
above. The use of `--config Release` in build commands is needed to properly
support multi-configuration tools (like Visual Studio for example) and can be
skipped for other build systems (like Makefile).

To enable link-time optimisation, also add `-DBENCHMARK_ENABLE_LTO=true` when
generating the build system files.

If you are using gcc, you might need to set `GCC_AR` and `GCC_RANLIB` cmake
cache variables, if autodetection fails.

If you are using clang, you may need to set `LLVMAR_EXECUTABLE`,
`LLVMNM_EXECUTABLE` and `LLVMRANLIB_EXECUTABLE` cmake cache variables.

### Stable and Experimental Library Versions

The main branch contains the latest stable version of the benchmarking library;
the API of which can be considered largely stable, with source breaking changes
being made only upon the release of a new major version.

Newer, experimental, features are implemented and tested on the
[`v2` branch](https://github.com/google/benchmark/tree/v2). Users who wish
to use, test, and provide feedback on the new features are encouraged to try
this branch. However, this branch provides no stability guarantees and reserves
the right to change and break the API at any time.

## Usage

### Basic usage

Define a function that executes the code to measure, register it as a benchmark
function using the `BENCHMARK` macro, and ensure an appropriate `main` function
is available:

```c++
#include <benchmark/benchmark.h>

static void BM_StringCreation(benchmark::State& state) {
  for (auto _ : state)
    std::string empty_string;
}
// Register the function as a benchmark
BENCHMARK(BM_StringCreation);

// Define another benchmark
static void BM_StringCopy(benchmark::State& state) {
  std::string x = "hello";
  for (auto _ : state)
    std::string copy(x);
}
BENCHMARK(BM_StringCopy);

BENCHMARK_MAIN();
```

To run the benchmark, compile and link against the `benchmark` library
(libbenchmark.a/.so). If you followed the build steps above, this library will 
be under the build directory you created.

```bash
# Example on linux after running the build steps above. Assumes the
# `benchmark` and `build` directories are under the current directory.
$ g++ mybenchmark.cc -std=c++11 -isystem benchmark/include \
  -Lbenchmark/build/src -lbenchmark -lpthread -o mybenchmark
```

Alternatively, link against the `benchmark_main` library and remove
`BENCHMARK_MAIN();` above to get the same behavior.

The compiled executable will run all benchmarks by default. Pass the `--help`
flag for option information or see the guide below.

### Usage with CMake

If using CMake, it is recommended to link against the project-provided
`benchmark::benchmark` and `benchmark::benchmark_main` targets using
`target_link_libraries`.
It is possible to use ```find_package``` to import an installed version of the
library.
```cmake
find_package(benchmark REQUIRED)
```
Alternatively, ```add_subdirectory``` will incorporate the library directly in
to one's CMake project.
```cmake
add_subdirectory(benchmark)
```
Either way, link to the library as follows.
```cmake
target_link_libraries(MyTarget benchmark::benchmark)
```

## Platform Specific Build Instructions

### Building with GCC

When the library is built using GCC it is necessary to link with the pthread
library due to how GCC implements `std::thread`. Failing to link to pthread will
lead to runtime exceptions (unless you're using libc++), not linker errors. See
[issue #67](https://github.com/google/benchmark/issues/67) for more details. You
can link to pthread by adding `-pthread` to your linker command. Note, you can
also use `-lpthread`, but there are potential issues with ordering of command
line parameters if you use that.

### Building with Visual Studio 2015 or 2017

The `shlwapi` library (`-lshlwapi`) is required to support a call to `CPUInfo` which reads the registry. Either add `shlwapi.lib` under `[ Configuration Properties > Linker > Input ]`, or use the following:

```
// Alternatively, can add libraries using linker options.
#ifdef _WIN32
#pragma comment ( lib, "Shlwapi.lib" )
#ifdef _DEBUG
#pragma comment ( lib, "benchmarkd.lib" )
#else
#pragma comment ( lib, "benchmark.lib" )
#endif
#endif
```

Can also use the graphical version of CMake:
* Open `CMake GUI`.
* Under `Where to build the binaries`, same path as source plus `build`.
* Under `CMAKE_INSTALL_PREFIX`, same path as source plus `install`.
* Click `Configure`, `Generate`, `Open Project`.
* If build fails, try deleting entire directory and starting again, or unticking options to build less.

### Building with Intel 2015 Update 1 or Intel System Studio Update 4

See instructions for building with Visual Studio. Once built, right click on the solution and change the build to Intel.

### Building on Solaris

If you're running benchmarks on solaris, you'll want the kstat library linked in
too (`-lkstat`).

## User Guide

### Command Line

[Output Formats](#output-formats)

[Output Files](#output-files)

[Running Benchmarks](#running-benchmarks)

[Running a Subset of Benchmarks](#running-a-subset-of-benchmarks)

[Result Comparison](#result-comparison)

### Library

[Runtime and Reporting Considerations](#runtime-and-reporting-considerations)

[Passing Arguments](#passing-arguments)

[Calculating Asymptotic Complexity](#asymptotic-complexity)

[Templated Benchmarks](#templated-benchmarks)

[Fixtures](#fixtures)

[Custom Counters](#custom-counters)

[Multithreaded Benchmarks](#multithreaded-benchmarks)

[CPU Timers](#cpu-timers)

[Manual Timing](#manual-timing)

[Setting the Time Unit](#setting-the-time-unit)

[Preventing Optimization](#preventing-optimization)

[Reporting Statistics](#reporting-statistics)

[Custom Statistics](#custom-statistics)

[Using RegisterBenchmark](#using-register-benchmark)

[Exiting with an Error](#exiting-with-an-error)

[A Faster KeepRunning Loop](#a-faster-keep-running-loop)

[Disabling CPU Frequency Scaling](#disabling-cpu-frequency-scaling)


<a name="output-formats" />

### Output Formats

The library supports multiple output formats. Use the
`--benchmark_format=<console|json|csv>` flag (or set the
`BENCHMARK_FORMAT=<console|json|csv>` environment variable) to set
the format type. `console` is the default format.

The Console format is intended to be a human readable format. By default
the format generates color output. Context is output on stderr and the
tabular data on stdout. Example tabular output looks like:

```
Benchmark                               Time(ns)    CPU(ns) Iterations
----------------------------------------------------------------------
BM_SetInsert/1024/1                        28928      29349      23853  133.097kB/s   33.2742k items/s
BM_SetInsert/1024/8                        32065      32913      21375  949.487kB/s   237.372k items/s
BM_SetInsert/1024/10                       33157      33648      21431  1.13369MB/s   290.225k items/s
```

The JSON format outputs human readable json split into two top level attributes.
The `context` attribute contains information about the run in general, including
information about the CPU and the date.
The `benchmarks` attribute contains a list of every benchmark run. Example json
output looks like:

```json
{
  "context": {
    "date": "2015/03/17-18:40:25",
    "num_cpus": 40,
    "mhz_per_cpu": 2801,
    "cpu_scaling_enabled": false,
    "build_type": "debug"
  },
  "benchmarks": [
    {
      "name": "BM_SetInsert/1024/1",
      "iterations": 94877,
      "real_time": 29275,
      "cpu_time": 29836,
      "bytes_per_second": 134066,
      "items_per_second": 33516
    },
    {
      "name": "BM_SetInsert/1024/8",
      "iterations": 21609,
      "real_time": 32317,
      "cpu_time": 32429,
      "bytes_per_second": 986770,
      "items_per_second": 246693
    },
    {
      "name": "BM_SetInsert/1024/10",
      "iterations": 21393,
      "real_time": 32724,
      "cpu_time": 33355,
      "bytes_per_second": 1199226,
      "items_per_second": 299807
    }
  ]
}
```

The CSV format outputs comma-separated values. The `context` is output on stderr
and the CSV itself on stdout. Example CSV output looks like:

```
name,iterations,real_time,cpu_time,bytes_per_second,items_per_second,label
"BM_SetInsert/1024/1",65465,17890.7,8407.45,475768,118942,
"BM_SetInsert/1024/8",116606,18810.1,9766.64,3.27646e+06,819115,
"BM_SetInsert/1024/10",106365,17238.4,8421.53,4.74973e+06,1.18743e+06,
```

<a name="output-files" />

### Output Files

Write benchmark results to a file with the `--benchmark_out=<filename>` option
(or set `BENCHMARK_OUT`). Specify the output format with
`--benchmark_out_format={json|console|csv}` (or set
`BENCHMARK_OUT_FORMAT={json|console|csv}`). Note that specifying
`--benchmark_out` does not suppress the console output.

<a name="running-benchmarks" />

### Running Benchmarks

Benchmarks are executed by running the produced binaries. Benchmarks binaries,
by default, accept options that may be specified either through their command
line interface or by setting environment variables before execution. For every
`--option_flag=<value>` CLI switch, a corresponding environment variable
`OPTION_FLAG=<value>` exist and is used as default if set (CLI switches always
 prevails). A complete list of CLI options is available running benchmarks
 with the `--help` switch.

<a name="running-a-subset-of-benchmarks" />

### Running a Subset of Benchmarks

The `--benchmark_filter=<regex>` option (or `BENCHMARK_FILTER=<regex>`
environment variable) can be used to only run the benchmarks that match
the specified `<regex>`. For example:

```bash
$ ./run_benchmarks.x --benchmark_filter=BM_memcpy/32
Run on (1 X 2300 MHz CPU )
2016-06-25 19:34:24
Benchmark              Time           CPU Iterations
----------------------------------------------------
BM_memcpy/32          11 ns         11 ns   79545455
BM_memcpy/32k       2181 ns       2185 ns     324074
BM_memcpy/32          12 ns         12 ns   54687500
BM_memcpy/32k       1834 ns       1837 ns     357143
```

<a name="result-comparison" />

### Result comparison

It is possible to compare the benchmarking results.
See [Additional Tooling Documentation](docs/tools.md)

<a name="runtime-and-reporting-considerations" />

### Runtime and Reporting Considerations

When the benchmark binary is executed, each benchmark function is run serially.
The number of iterations to run is determined dynamically by running the
benchmark a few times and measuring the time taken and ensuring that the
ultimate result will be statistically stable. As such, faster benchmark
functions will be run for more iterations than slower benchmark functions, and
the number of iterations is thus reported.

In all cases, the number of iterations for which the benchmark is run is
governed by the amount of time the benchmark takes. Concretely, the number of
iterations is at least one, not more than 1e9, until CPU time is greater than
the minimum time, or the wallclock time is 5x minimum time. The minimum time is
set per benchmark by calling `MinTime` on the registered benchmark object.

Average timings are then reported over the iterations run. If multiple
repetitions are requested using the `--benchmark_repetitions` command-line
option, or at registration time, the benchmark function will be run several
times and statistical results across these repetitions will also be reported.

As well as the per-benchmark entries, a preamble in the report will include
information about the machine on which the benchmarks are run.

<a name="passing-arguments" />

### Passing Arguments

Sometimes a family of benchmarks can be implemented with just one routine that
takes an extra argument to specify which one of the family of benchmarks to
run. For example, the following code defines a family of benchmarks for
measuring the speed of `memcpy()` calls of different lengths:

```c++
static void BM_memcpy(benchmark::State& state) {
  char* src = new char[state.range(0)];
  char* dst = new char[state.range(0)];
  memset(src, 'x', state.range(0));
  for (auto _ : state)
    memcpy(dst, src, state.range(0));
  state.SetBytesProcessed(int64_t(state.iterations()) *
                          int64_t(state.range(0)));
  delete[] src;
  delete[] dst;
}
BENCHMARK(BM_memcpy)->Arg(8)->Arg(64)->Arg(512)->Arg(1<<10)->Arg(8<<10);
```

The preceding code is quite repetitive, and can be replaced with the following
short-hand. The following invocation will pick a few appropriate arguments in
the specified range and will generate a benchmark for each such argument.

```c++
BENCHMARK(BM_memcpy)->Range(8, 8<<10);
```

By default the arguments in the range are generated in multiples of eight and
the command above selects [ 8, 64, 512, 4k, 8k ]. In the following code the
range multiplier is changed to multiples of two.

```c++
BENCHMARK(BM_memcpy)->RangeMultiplier(2)->Range(8, 8<<10);
```

Now arguments generated are [ 8, 16, 32, 64, 128, 256, 512, 1024, 2k, 4k, 8k ].

The preceding code shows a method of defining a sparse range.  The following
example shows a method of defining a dense range. It is then used to benchmark
the performance of `std::vector` initialization for uniformly increasing sizes.

```c++
static void BM_DenseRange(benchmark::State& state) {
  for(auto _ : state) {
    std::vector<int> v(state.range(0), state.range(0));
    benchmark::DoNotOptimize(v.data());
    benchmark::ClobberMemory();
  }
}
BENCHMARK(BM_DenseRange)->DenseRange(0, 1024, 128);
```

Now arguments generated are [ 0, 128, 256, 384, 512, 640, 768, 896, 1024 ].

You might have a benchmark that depends on two or more inputs. For example, the
following code defines a family of benchmarks for measuring the speed of set
insertion.

```c++
static void BM_SetInsert(benchmark::State& state) {
  std::set<int> data;
  for (auto _ : state) {
    state.PauseTiming();
    data = ConstructRandomSet(state.range(0));
    state.ResumeTiming();
    for (int j = 0; j < state.range(1); ++j)
      data.insert(RandomNumber());
  }
}
BENCHMARK(BM_SetInsert)
    ->Args({1<<10, 128})
    ->Args({2<<10, 128})
    ->Args({4<<10, 128})
    ->Args({8<<10, 128})
    ->Args({1<<10, 512})
    ->Args({2<<10, 512})
    ->Args({4<<10, 512})
    ->Args({8<<10, 512});
```

The preceding code is quite repetitive, and can be replaced with the following
short-hand. The following macro will pick a few appropriate arguments in the
product of the two specified ranges and will generate a benchmark for each such
pair.

```c++
BENCHMARK(BM_SetInsert)->Ranges({{1<<10, 8<<10}, {128, 512}});
```

Some benchmarks may require specific argument values that cannot be expressed
with `Ranges`. In this case, `ArgsProduct` offers the ability to generate a
benchmark input for each combination in the product of the supplied vectors.

```c++
BENCHMARK(BM_SetInsert)
    ->ArgsProduct({{1<<10, 3<<10, 8<<10}, {20, 40, 60, 80}})
// would generate the same benchmark arguments as
BENCHMARK(BM_SetInsert)
    ->Args({1<<10, 20})
    ->Args({3<<10, 20})
    ->Args({8<<10, 20})
    ->Args({3<<10, 40})
    ->Args({8<<10, 40})
    ->Args({1<<10, 40})
    ->Args({1<<10, 60})
    ->Args({3<<10, 60})
    ->Args({8<<10, 60})
    ->Args({1<<10, 80})
    ->Args({3<<10, 80})
    ->Args({8<<10, 80});
```

For more complex patterns of inputs, passing a custom function to `Apply` allows
programmatic specification of an arbitrary set of arguments on which to run the
benchmark. The following example enumerates a dense range on one parameter,
and a sparse range on the second.

```c++
static void CustomArguments(benchmark::internal::Benchmark* b) {
  for (int i = 0; i <= 10; ++i)
    for (int j = 32; j <= 1024*1024; j *= 8)
      b->Args({i, j});
}
BENCHMARK(BM_SetInsert)->Apply(CustomArguments);
```

#### Passing Arbitrary Arguments to a Benchmark

In C++11 it is possible to define a benchmark that takes an arbitrary number
of extra arguments. The `BENCHMARK_CAPTURE(func, test_case_name, ...args)`
macro creates a benchmark that invokes `func`  with the `benchmark::State` as
the first argument followed by the specified `args...`.
The `test_case_name` is appended to the name of the benchmark and
should describe the values passed.

```c++
template <class ...ExtraArgs>
void BM_takes_args(benchmark::State& state, ExtraArgs&&... extra_args) {
  [...]
}
// Registers a benchmark named "BM_takes_args/int_string_test" that passes
// the specified values to `extra_args`.
BENCHMARK_CAPTURE(BM_takes_args, int_string_test, 42, std::string("abc"));
```

Note that elements of `...args` may refer to global variables. Users should
avoid modifying global state inside of a benchmark.

<a name="asymptotic-complexity" />

### Calculating Asymptotic Complexity (Big O)

Asymptotic complexity might be calculated for a family of benchmarks. The
following code will calculate the coefficient for the high-order term in the
running time and the normalized root-mean square error of string comparison.

```c++
static void BM_StringCompare(benchmark::State& state) {
  std::string s1(state.range(0), '-');
  std::string s2(state.range(0), '-');
  for (auto _ : state) {
    benchmark::DoNotOptimize(s1.compare(s2));
  }
  state.SetComplexityN(state.range(0));
}
BENCHMARK(BM_StringCompare)
    ->RangeMultiplier(2)->Range(1<<10, 1<<18)->Complexity(benchmark::oN);
```

As shown in the following invocation, asymptotic complexity might also be
calculated automatically.

```c++
BENCHMARK(BM_StringCompare)
    ->RangeMultiplier(2)->Range(1<<10, 1<<18)->Complexity();
```

The following code will specify asymptotic complexity with a lambda function,
that might be used to customize high-order term calculation.

```c++
BENCHMARK(BM_StringCompare)->RangeMultiplier(2)
    ->Range(1<<10, 1<<18)->Complexity([](benchmark::IterationCount n)->double{return n; });
```

<a name="templated-benchmarks" />

### Templated Benchmarks

This example produces and consumes messages of size `sizeof(v)` `range_x`
times. It also outputs throughput in the absence of multiprogramming.

```c++
template <class Q> void BM_Sequential(benchmark::State& state) {
  Q q;
  typename Q::value_type v;
  for (auto _ : state) {
    for (int i = state.range(0); i--; )
      q.push(v);
    for (int e = state.range(0); e--; )
      q.Wait(&v);
  }
  // actually messages, not bytes:
  state.SetBytesProcessed(
      static_cast<int64_t>(state.iterations())*state.range(0));
}
BENCHMARK_TEMPLATE(BM_Sequential, WaitQueue<int>)->Range(1<<0, 1<<10);
```

Three macros are provided for adding benchmark templates.

```c++
#ifdef BENCHMARK_HAS_CXX11
#define BENCHMARK_TEMPLATE(func, ...) // Takes any number of parameters.
#else // C++ < C++11
#define BENCHMARK_TEMPLATE(func, arg1)
#endif
#define BENCHMARK_TEMPLATE1(func, arg1)
#define BENCHMARK_TEMPLATE2(func, arg1, arg2)
```

<a name="fixtures" />

### Fixtures

Fixture tests are created by first defining a type that derives from
`::benchmark::Fixture` and then creating/registering the tests using the
following macros:

* `BENCHMARK_F(ClassName, Method)`
* `BENCHMARK_DEFINE_F(ClassName, Method)`
* `BENCHMARK_REGISTER_F(ClassName, Method)`

For Example:

```c++
class MyFixture : public benchmark::Fixture {
public:
  void SetUp(const ::benchmark::State& state) {
  }

  void TearDown(const ::benchmark::State& state) {
  }
};

BENCHMARK_F(MyFixture, FooTest)(benchmark::State& st) {
   for (auto _ : st) {
     ...
  }
}

BENCHMARK_DEFINE_F(MyFixture, BarTest)(benchmark::State& st) {
   for (auto _ : st) {
     ...
  }
}
/* BarTest is NOT registered */
BENCHMARK_REGISTER_F(MyFixture, BarTest)->Threads(2);
/* BarTest is now registered */
```

#### Templated Fixtures

Also you can create templated fixture by using the following macros:

* `BENCHMARK_TEMPLATE_F(ClassName, Method, ...)`
* `BENCHMARK_TEMPLATE_DEFINE_F(ClassName, Method, ...)`

For example:

```c++
template<typename T>
class MyFixture : public benchmark::Fixture {};

BENCHMARK_TEMPLATE_F(MyFixture, IntTest, int)(benchmark::State& st) {
   for (auto _ : st) {
     ...
  }
}

BENCHMARK_TEMPLATE_DEFINE_F(MyFixture, DoubleTest, double)(benchmark::State& st) {
   for (auto _ : st) {
     ...
  }
}

BENCHMARK_REGISTER_F(MyFixture, DoubleTest)->Threads(2);
```

<a name="custom-counters" />

### Custom Counters

You can add your own counters with user-defined names. The example below
will add columns "Foo", "Bar" and "Baz" in its output:

```c++
static void UserCountersExample1(benchmark::State& state) {
  double numFoos = 0, numBars = 0, numBazs = 0;
  for (auto _ : state) {
    // ... count Foo,Bar,Baz events
  }
  state.counters["Foo"] = numFoos;
  state.counters["Bar"] = numBars;
  state.counters["Baz"] = numBazs;
}
```

The `state.counters` object is a `std::map` with `std::string` keys
and `Counter` values. The latter is a `double`-like class, via an implicit
conversion to `double&`. Thus you can use all of the standard arithmetic
assignment operators (`=,+=,-=,*=,/=`) to change the value of each counter.

In multithreaded benchmarks, each counter is set on the calling thread only.
When the benchmark finishes, the counters from each thread will be summed;
the resulting sum is the value which will be shown for the benchmark.

The `Counter` constructor accepts three parameters: the value as a `double`
; a bit flag which allows you to show counters as rates, and/or as per-thread
iteration, and/or as per-thread averages, and/or iteration invariants,
and/or finally inverting the result; and a flag specifying the 'unit' - i.e.
is 1k a 1000 (default, `benchmark::Counter::OneK::kIs1000`), or 1024
(`benchmark::Counter::OneK::kIs1024`)?

```c++
  // sets a simple counter
  state.counters["Foo"] = numFoos;

  // Set the counter as a rate. It will be presented divided
  // by the duration of the benchmark.
  // Meaning: per one second, how many 'foo's are processed?
  state.counters["FooRate"] = Counter(numFoos, benchmark::Counter::kIsRate);

  // Set the counter as a rate. It will be presented divided
  // by the duration of the benchmark, and the result inverted.
  // Meaning: how many seconds it takes to process one 'foo'?
  state.counters["FooInvRate"] = Counter(numFoos, benchmark::Counter::kIsRate | benchmark::Counter::kInvert);

  // Set the counter as a thread-average quantity. It will
  // be presented divided by the number of threads.
  state.counters["FooAvg"] = Counter(numFoos, benchmark::Counter::kAvgThreads);

  // There's also a combined flag:
  state.counters["FooAvgRate"] = Counter(numFoos,benchmark::Counter::kAvgThreadsRate);

  // This says that we process with the rate of state.range(0) bytes every iteration:
  state.counters["BytesProcessed"] = Counter(state.range(0), benchmark::Counter::kIsIterationInvariantRate, benchmark::Counter::OneK::kIs1024);
```

When you're compiling in C++11 mode or later you can use `insert()` with
`std::initializer_list`:

```c++
  // With C++11, this can be done:
  state.counters.insert({{"Foo", numFoos}, {"Bar", numBars}, {"Baz", numBazs}});
  // ... instead of:
  state.counters["Foo"] = numFoos;
  state.counters["Bar"] = numBars;
  state.counters["Baz"] = numBazs;
```

#### Counter Reporting

When using the console reporter, by default, user counters are printed at
the end after the table, the same way as ``bytes_processed`` and
``items_processed``. This is best for cases in which there are few counters,
or where there are only a couple of lines per benchmark. Here's an example of
the default output:

```
------------------------------------------------------------------------------
Benchmark                        Time           CPU Iterations UserCounters...
------------------------------------------------------------------------------
BM_UserCounter/threads:8      2248 ns      10277 ns      68808 Bar=16 Bat=40 Baz=24 Foo=8
BM_UserCounter/threads:1      9797 ns       9788 ns      71523 Bar=2 Bat=5 Baz=3 Foo=1024m
BM_UserCounter/threads:2      4924 ns       9842 ns      71036 Bar=4 Bat=10 Baz=6 Foo=2
BM_UserCounter/threads:4      2589 ns      10284 ns      68012 Bar=8 Bat=20 Baz=12 Foo=4
BM_UserCounter/threads:8      2212 ns      10287 ns      68040 Bar=16 Bat=40 Baz=24 Foo=8
BM_UserCounter/threads:16     1782 ns      10278 ns      68144 Bar=32 Bat=80 Baz=48 Foo=16
BM_UserCounter/threads:32     1291 ns      10296 ns      68256 Bar=64 Bat=160 Baz=96 Foo=32
BM_UserCounter/threads:4      2615 ns      10307 ns      68040 Bar=8 Bat=20 Baz=12 Foo=4
BM_Factorial                    26 ns         26 ns   26608979 40320
BM_Factorial/real_time          26 ns         26 ns   26587936 40320
BM_CalculatePiRange/1           16 ns         16 ns   45704255 0
BM_CalculatePiRange/8           73 ns         73 ns    9520927 3.28374
BM_CalculatePiRange/64         609 ns        609 ns    1140647 3.15746
BM_CalculatePiRange/512       4900 ns       4901 ns     142696 3.14355
```

If this doesn't suit you, you can print each counter as a table column by
passing the flag `--benchmark_counters_tabular=true` to the benchmark
application. This is best for cases in which there are a lot of counters, or
a lot of lines per individual benchmark. Note that this will trigger a
reprinting of the table header any time the counter set changes between
individual benchmarks. Here's an example of corresponding output when
`--benchmark_counters_tabular=true` is passed:

```
---------------------------------------------------------------------------------------
Benchmark                        Time           CPU Iterations    Bar   Bat   Baz   Foo
---------------------------------------------------------------------------------------
BM_UserCounter/threads:8      2198 ns       9953 ns      70688     16    40    24     8
BM_UserCounter/threads:1      9504 ns       9504 ns      73787      2     5     3     1
BM_UserCounter/threads:2      4775 ns       9550 ns      72606      4    10     6     2
BM_UserCounter/threads:4      2508 ns       9951 ns      70332      8    20    12     4
BM_UserCounter/threads:8      2055 ns       9933 ns      70344     16    40    24     8
BM_UserCounter/threads:16     1610 ns       9946 ns      70720     32    80    48    16
BM_UserCounter/threads:32     1192 ns       9948 ns      70496     64   160    96    32
BM_UserCounter/threads:4      2506 ns       9949 ns      70332      8    20    12     4
--------------------------------------------------------------
Benchmark                        Time           CPU Iterations
--------------------------------------------------------------
BM_Factorial                    26 ns         26 ns   26392245 40320
BM_Factorial/real_time          26 ns         26 ns   26494107 40320
BM_CalculatePiRange/1           15 ns         15 ns   45571597 0
BM_CalculatePiRange/8           74 ns         74 ns    9450212 3.28374
BM_CalculatePiRange/64         595 ns        595 ns    1173901 3.15746
BM_CalculatePiRange/512       4752 ns       4752 ns     147380 3.14355
BM_CalculatePiRange/4k       37970 ns      37972 ns      18453 3.14184
BM_CalculatePiRange/32k     303733 ns     303744 ns       2305 3.14162
BM_CalculatePiRange/256k   2434095 ns    2434186 ns        288 3.1416
BM_CalculatePiRange/1024k  9721140 ns    9721413 ns         71 3.14159
BM_CalculatePi/threads:8      2255 ns       9943 ns      70936
```

Note above the additional header printed when the benchmark changes from
``BM_UserCounter`` to ``BM_Factorial``. This is because ``BM_Factorial`` does
not have the same counter set as ``BM_UserCounter``.

<a name="multithreaded-benchmarks"/>

### Multithreaded Benchmarks

In a multithreaded test (benchmark invoked by multiple threads simultaneously),
it is guaranteed that none of the threads will start until all have reached
the start of the benchmark loop, and all will have finished before any thread
exits the benchmark loop. (This behavior is also provided by the `KeepRunning()`
API) As such, any global setup or teardown can be wrapped in a check against the thread
index:

```c++
static void BM_MultiThreaded(benchmark::State& state) {
  if (state.thread_index == 0) {
    // Setup code here.
  }
  for (auto _ : state) {
    // Run the test as normal.
  }
  if (state.thread_index == 0) {
    // Teardown code here.
  }
}
BENCHMARK(BM_MultiThreaded)->Threads(2);
```

If the benchmarked code itself uses threads and you want to compare it to
single-threaded code, you may want to use real-time ("wallclock") measurements
for latency comparisons:

```c++
BENCHMARK(BM_test)->Range(8, 8<<10)->UseRealTime();
```

Without `UseRealTime`, CPU time is used by default.

<a name="cpu-timers" />

### CPU Timers

By default, the CPU timer only measures the time spent by the main thread.
If the benchmark itself uses threads internally, this measurement may not
be what you are looking for. Instead, there is a way to measure the total
CPU usage of the process, by all the threads.

```c++
void callee(int i);

static void MyMain(int size) {
#pragma omp parallel for
  for(int i = 0; i < size; i++)
    callee(i);
}

static void BM_OpenMP(benchmark::State& state) {
  for (auto _ : state)
    MyMain(state.range(0));
}

// Measure the time spent by the main thread, use it to decide for how long to
// run the benchmark loop. Depending on the internal implementation detail may
// measure to anywhere from near-zero (the overhead spent before/after work
// handoff to worker thread[s]) to the whole single-thread time.
BENCHMARK(BM_OpenMP)->Range(8, 8<<10);

// Measure the user-visible time, the wall clock (literally, the time that
// has passed on the clock on the wall), use it to decide for how long to
// run the benchmark loop. This will always be meaningful, an will match the
// time spent by the main thread in single-threaded case, in general decreasing
// with the number of internal threads doing the work.
BENCHMARK(BM_OpenMP)->Range(8, 8<<10)->UseRealTime();

// Measure the total CPU consumption, use it to decide for how long to
// run the benchmark loop. This will always measure to no less than the
// time spent by the main thread in single-threaded case.
BENCHMARK(BM_OpenMP)->Range(8, 8<<10)->MeasureProcessCPUTime();

// A mixture of the last two. Measure the total CPU consumption, but use the
// wall clock to decide for how long to run the benchmark loop.
BENCHMARK(BM_OpenMP)->Range(8, 8<<10)->MeasureProcessCPUTime()->UseRealTime();
```

#### Controlling Timers

Normally, the entire duration of the work loop (`for (auto _ : state) {}`)
is measured. But sometimes, it is necessary to do some work inside of
that loop, every iteration, but without counting that time to the benchmark time.
That is possible, although it is not recommended, since it has high overhead.

```c++
static void BM_SetInsert_With_Timer_Control(benchmark::State& state) {
  std::set<int> data;
  for (auto _ : state) {
    state.PauseTiming(); // Stop timers. They will not count until they are resumed.
    data = ConstructRandomSet(state.range(0)); // Do something that should not be measured
    state.ResumeTiming(); // And resume timers. They are now counting again.
    // The rest will be measured.
    for (int j = 0; j < state.range(1); ++j)
      data.insert(RandomNumber());
  }
}
BENCHMARK(BM_SetInsert_With_Timer_Control)->Ranges({{1<<10, 8<<10}, {128, 512}});
```

<a name="manual-timing" />

### Manual Timing

For benchmarking something for which neither CPU time nor real-time are
correct or accurate enough, completely manual timing is supported using
the `UseManualTime` function.

When `UseManualTime` is used, the benchmarked code must call
`SetIterationTime` once per iteration of the benchmark loop to
report the manually measured time.

An example use case for this is benchmarking GPU execution (e.g. OpenCL
or CUDA kernels, OpenGL or Vulkan or Direct3D draw calls), which cannot
be accurately measured using CPU time or real-time. Instead, they can be
measured accurately using a dedicated API, and these measurement results
can be reported back with `SetIterationTime`.

```c++
static void BM_ManualTiming(benchmark::State& state) {
  int microseconds = state.range(0);
  std::chrono::duration<double, std::micro> sleep_duration {
    static_cast<double>(microseconds)
  };

  for (auto _ : state) {
    auto start = std::chrono::high_resolution_clock::now();
    // Simulate some useful workload with a sleep
    std::this_thread::sleep_for(sleep_duration);
    auto end = std::chrono::high_resolution_clock::now();

    auto elapsed_seconds =
      std::chrono::duration_cast<std::chrono::duration<double>>(
        end - start);

    state.SetIterationTime(elapsed_seconds.count());
  }
}
BENCHMARK(BM_ManualTiming)->Range(1, 1<<17)->UseManualTime();
```

<a name="setting-the-time-unit" />

### Setting the Time Unit

If a benchmark runs a few milliseconds it may be hard to visually compare the
measured times, since the output data is given in nanoseconds per default. In
order to manually set the time unit, you can specify it manually:

```c++
BENCHMARK(BM_test)->Unit(benchmark::kMillisecond);
```

<a name="preventing-optimization" />

### Preventing Optimization

To prevent a value or expression from being optimized away by the compiler
the `benchmark::DoNotOptimize(...)` and `benchmark::ClobberMemory()`
functions can be used.

```c++
static void BM_test(benchmark::State& state) {
  for (auto _ : state) {
      int x = 0;
      for (int i=0; i < 64; ++i) {
        benchmark::DoNotOptimize(x += i);
      }
  }
}
```

`DoNotOptimize(<expr>)` forces the  *result* of `<expr>` to be stored in either
memory or a register. For GNU based compilers it acts as read/write barrier
for global memory. More specifically it forces the compiler to flush pending
writes to memory and reload any other values as necessary.

Note that `DoNotOptimize(<expr>)` does not prevent optimizations on `<expr>`
in any way. `<expr>` may even be removed entirely when the result is already
known. For example:

```c++
  /* Example 1: `<expr>` is removed entirely. */
  int foo(int x) { return x + 42; }
  while (...) DoNotOptimize(foo(0)); // Optimized to DoNotOptimize(42);

  /*  Example 2: Result of '<expr>' is only reused */
  int bar(int) __attribute__((const));
  while (...) DoNotOptimize(bar(0)); // Optimized to:
  // int __result__ = bar(0);
  // while (...) DoNotOptimize(__result__);
```

The second tool for preventing optimizations is `ClobberMemory()`. In essence
`ClobberMemory()` forces the compiler to perform all pending writes to global
memory. Memory managed by block scope objects must be "escaped" using
`DoNotOptimize(...)` before it can be clobbered. In the below example
`ClobberMemory()` prevents the call to `v.push_back(42)` from being optimized
away.

```c++
static void BM_vector_push_back(benchmark::State& state) {
  for (auto _ : state) {
    std::vector<int> v;
    v.reserve(1);
    benchmark::DoNotOptimize(v.data()); // Allow v.data() to be clobbered.
    v.push_back(42);
    benchmark::ClobberMemory(); // Force 42 to be written to memory.
  }
}
```

Note that `ClobberMemory()` is only available for GNU or MSVC based compilers.

<a name="reporting-statistics" />

### Statistics: Reporting the Mean, Median and Standard Deviation of Repeated Benchmarks

By default each benchmark is run once and that single result is reported.
However benchmarks are often noisy and a single result may not be representative
of the overall behavior. For this reason it's possible to repeatedly rerun the
benchmark.

The number of runs of each benchmark is specified globally by the
`--benchmark_repetitions` flag or on a per benchmark basis by calling
`Repetitions` on the registered benchmark object. When a benchmark is run more
than once the mean, median and standard deviation of the runs will be reported.

Additionally the `--benchmark_report_aggregates_only={true|false}`,
`--benchmark_display_aggregates_only={true|false}` flags or
`ReportAggregatesOnly(bool)`, `DisplayAggregatesOnly(bool)` functions can be
used to change how repeated tests are reported. By default the result of each
repeated run is reported. When `report aggregates only` option is `true`,
only the aggregates (i.e. mean, median and standard deviation, maybe complexity
measurements if they were requested) of the runs is reported, to both the
reporters - standard output (console), and the file.
However when only the `display aggregates only` option is `true`,
only the aggregates are displayed in the standard output, while the file
output still contains everything.
Calling `ReportAggregatesOnly(bool)` / `DisplayAggregatesOnly(bool)` on a
registered benchmark object overrides the value of the appropriate flag for that
benchmark.

<a name="custom-statistics" />

### Custom Statistics

While having mean, median and standard deviation is nice, this may not be
enough for everyone. For example you may want to know what the largest
observation is, e.g. because you have some real-time constraints. This is easy.
The following code will specify a custom statistic to be calculated, defined
by a lambda function.

```c++
void BM_spin_empty(benchmark::State& state) {
  for (auto _ : state) {
    for (int x = 0; x < state.range(0); ++x) {
      benchmark::DoNotOptimize(x);
    }
  }
}

BENCHMARK(BM_spin_empty)
  ->ComputeStatistics("max", [](const std::vector<double>& v) -> double {
    return *(std::max_element(std::begin(v), std::end(v)));
  })
  ->Arg(512);
```

<a name="using-register-benchmark" />

### Using RegisterBenchmark(name, fn, args...)

The `RegisterBenchmark(name, func, args...)` function provides an alternative
way to create and register benchmarks.
`RegisterBenchmark(name, func, args...)` creates, registers, and returns a
pointer to a new benchmark with the specified `name` that invokes
`func(st, args...)` where `st` is a `benchmark::State` object.

Unlike the `BENCHMARK` registration macros, which can only be used at the global
scope, the `RegisterBenchmark` can be called anywhere. This allows for
benchmark tests to be registered programmatically.

Additionally `RegisterBenchmark` allows any callable object to be registered
as a benchmark. Including capturing lambdas and function objects.

For Example:
```c++
auto BM_test = [](benchmark::State& st, auto Inputs) { /* ... */ };

int main(int argc, char** argv) {
  for (auto& test_input : { /* ... */ })
      benchmark::RegisterBenchmark(test_input.name(), BM_test, test_input);
  benchmark::Initialize(&argc, argv);
  benchmark::RunSpecifiedBenchmarks();
}
```

<a name="exiting-with-an-error" />

### Exiting with an Error

When errors caused by external influences, such as file I/O and network
communication, occur within a benchmark the
`State::SkipWithError(const char* msg)` function can be used to skip that run
of benchmark and report the error. Note that only future iterations of the
`KeepRunning()` are skipped. For the ranged-for version of the benchmark loop
Users must explicitly exit the loop, otherwise all iterations will be performed.
Users may explicitly return to exit the benchmark immediately.

The `SkipWithError(...)` function may be used at any point within the benchmark,
including before and after the benchmark loop. Moreover, if `SkipWithError(...)`
has been used, it is not required to reach the benchmark loop and one may return
from the benchmark function early.

For example:

```c++
static void BM_test(benchmark::State& state) {
  auto resource = GetResource();
  if (!resource.good()) {
    state.SkipWithError("Resource is not good!");
    // KeepRunning() loop will not be entered.
  }
  while (state.KeepRunning()) {
    auto data = resource.read_data();
    if (!resource.good()) {
      state.SkipWithError("Failed to read data!");
      break; // Needed to skip the rest of the iteration.
    }
    do_stuff(data);
  }
}

static void BM_test_ranged_fo(benchmark::State & state) {
  auto resource = GetResource();
  if (!resource.good()) {
    state.SkipWithError("Resource is not good!");
    return; // Early return is allowed when SkipWithError() has been used.
  }
  for (auto _ : state) {
    auto data = resource.read_data();
    if (!resource.good()) {
      state.SkipWithError("Failed to read data!");
      break; // REQUIRED to prevent all further iterations.
    }
    do_stuff(data);
  }
}
```
<a name="a-faster-keep-running-loop" />

### A Faster KeepRunning Loop

In C++11 mode, a ranged-based for loop should be used in preference to
the `KeepRunning` loop for running the benchmarks. For example:

```c++
static void BM_Fast(benchmark::State &state) {
  for (auto _ : state) {
    FastOperation();
  }
}
BENCHMARK(BM_Fast);
```

The reason the ranged-for loop is faster than using `KeepRunning`, is
because `KeepRunning` requires a memory load and store of the iteration count
ever iteration, whereas the ranged-for variant is able to keep the iteration count
in a register.

For example, an empty inner loop of using the ranged-based for method looks like:

```asm
# Loop Init
  mov rbx, qword ptr [r14 + 104]
  call benchmark::State::StartKeepRunning()
  test rbx, rbx
  je .LoopEnd
.LoopHeader: # =>This Inner Loop Header: Depth=1
  add rbx, -1
  jne .LoopHeader
.LoopEnd:
```

Compared to an empty `KeepRunning` loop, which looks like:

```asm
.LoopHeader: # in Loop: Header=BB0_3 Depth=1
  cmp byte ptr [rbx], 1
  jne .LoopInit
.LoopBody: # =>This Inner Loop Header: Depth=1
  mov rax, qword ptr [rbx + 8]
  lea rcx, [rax + 1]
  mov qword ptr [rbx + 8], rcx
  cmp rax, qword ptr [rbx + 104]
  jb .LoopHeader
  jmp .LoopEnd
.LoopInit:
  mov rdi, rbx
  call benchmark::State::StartKeepRunning()
  jmp .LoopBody
.LoopEnd:
```

Unless C++03 compatibility is required, the ranged-for variant of writing
the benchmark loop should be preferred.

<a name="disabling-cpu-frequency-scaling" />

### Disabling CPU Frequency Scaling

If you see this error:

```
***WARNING*** CPU scaling is enabled, the benchmark real time measurements may be noisy and will incur extra overhead.
```

you might want to disable the CPU frequency scaling while running the benchmark:

```bash
sudo cpupower frequency-set --governor performance
./mybench
sudo cpupower frequency-set --governor powersave
```
