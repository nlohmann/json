#include "benchmark/benchmark.h"

#include <cassert>
#include <iostream>
#include <set>
#include <vector>

class ArgsProductFixture : public ::benchmark::Fixture {
 public:
  ArgsProductFixture()
      : expectedValues({{0, 100, 2000, 30000},
                        {1, 15, 3, 8},
                        {1, 15, 3, 9},
                        {1, 15, 7, 8},
                        {1, 15, 7, 9},
                        {1, 15, 10, 8},
                        {1, 15, 10, 9},
                        {2, 15, 3, 8},
                        {2, 15, 3, 9},
                        {2, 15, 7, 8},
                        {2, 15, 7, 9},
                        {2, 15, 10, 8},
                        {2, 15, 10, 9},
                        {4, 5, 6, 11}}) {}

  void SetUp(const ::benchmark::State& state) {
    std::vector<int64_t> ranges = {state.range(0), state.range(1),
                                   state.range(2), state.range(3)};

    assert(expectedValues.find(ranges) != expectedValues.end());

    actualValues.insert(ranges);
  }

  // NOTE: This is not TearDown as we want to check after _all_ runs are
  // complete.
  virtual ~ArgsProductFixture() {
    if (actualValues != expectedValues) {
      std::cout << "EXPECTED\n";
      for (auto v : expectedValues) {
        std::cout << "{";
        for (int64_t iv : v) {
          std::cout << iv << ", ";
        }
        std::cout << "}\n";
      }
      std::cout << "ACTUAL\n";
      for (auto v : actualValues) {
        std::cout << "{";
        for (int64_t iv : v) {
          std::cout << iv << ", ";
        }
        std::cout << "}\n";
      }
    }
  }

  std::set<std::vector<int64_t>> expectedValues;
  std::set<std::vector<int64_t>> actualValues;
};

BENCHMARK_DEFINE_F(ArgsProductFixture, Empty)(benchmark::State& state) {
  for (auto _ : state) {
    int64_t product =
        state.range(0) * state.range(1) * state.range(2) * state.range(3);
    for (int64_t x = 0; x < product; x++) {
      benchmark::DoNotOptimize(x);
    }
  }
}

BENCHMARK_REGISTER_F(ArgsProductFixture, Empty)
    ->Args({0, 100, 2000, 30000})
    ->ArgsProduct({{1, 2}, {15}, {3, 7, 10}, {8, 9}})
    ->Args({4, 5, 6, 11});

BENCHMARK_MAIN();
