#include "benchmark/benchmark.h"

void BM_StringCreation(benchmark::State& state) {
    while (state.KeepRunning())
        std::string empty_string;
}

BENCHMARK(BM_StringCreation);

void BM_StringCopy(benchmark::State& state) {
    std::string x = "hello";
    while (state.KeepRunning())
        std::string copy(x);
}

BENCHMARK(BM_StringCopy);

BENCHMARK_MAIN();
