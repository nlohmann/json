#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace {

using namespace benchmark;
using namespace benchmark::internal;

TEST(BenchmarkNameTest, Empty) {
  const auto name = BenchmarkName();
  EXPECT_EQ(name.str(), std::string());
}

TEST(BenchmarkNameTest, FunctionName) {
  auto name = BenchmarkName();
  name.function_name = "function_name";
  EXPECT_EQ(name.str(), "function_name");
}

TEST(BenchmarkNameTest, FunctionNameAndArgs) {
  auto name = BenchmarkName();
  name.function_name = "function_name";
  name.args = "some_args:3/4/5";
  EXPECT_EQ(name.str(), "function_name/some_args:3/4/5");
}

TEST(BenchmarkNameTest, MinTime) {
  auto name = BenchmarkName();
  name.function_name = "function_name";
  name.args = "some_args:3/4";
  name.min_time = "min_time:3.4s";
  EXPECT_EQ(name.str(), "function_name/some_args:3/4/min_time:3.4s");
}

TEST(BenchmarkNameTest, Iterations) {
  auto name = BenchmarkName();
  name.function_name = "function_name";
  name.min_time = "min_time:3.4s";
  name.iterations = "iterations:42";
  EXPECT_EQ(name.str(), "function_name/min_time:3.4s/iterations:42");
}

TEST(BenchmarkNameTest, Repetitions) {
  auto name = BenchmarkName();
  name.function_name = "function_name";
  name.min_time = "min_time:3.4s";
  name.repetitions = "repetitions:24";
  EXPECT_EQ(name.str(), "function_name/min_time:3.4s/repetitions:24");
}

TEST(BenchmarkNameTest, TimeType) {
  auto name = BenchmarkName();
  name.function_name = "function_name";
  name.min_time = "min_time:3.4s";
  name.time_type = "hammer_time";
  EXPECT_EQ(name.str(), "function_name/min_time:3.4s/hammer_time");
}

TEST(BenchmarkNameTest, Threads) {
  auto name = BenchmarkName();
  name.function_name = "function_name";
  name.min_time = "min_time:3.4s";
  name.threads = "threads:256";
  EXPECT_EQ(name.str(), "function_name/min_time:3.4s/threads:256");
}

TEST(BenchmarkNameTest, TestEmptyFunctionName) {
  auto name = BenchmarkName();
  name.args = "first:3/second:4";
  name.threads = "threads:22";
  EXPECT_EQ(name.str(), "first:3/second:4/threads:22");
}

}  // end namespace
