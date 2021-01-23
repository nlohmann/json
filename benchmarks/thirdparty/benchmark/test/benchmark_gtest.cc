#include <vector>

#include "../src/benchmark_register.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace benchmark {
namespace internal {
namespace {

TEST(AddRangeTest, Simple) {
  std::vector<int> dst;
  AddRange(&dst, 1, 2, 2);
  EXPECT_THAT(dst, testing::ElementsAre(1, 2));
}

TEST(AddRangeTest, Simple64) {
  std::vector<int64_t> dst;
  AddRange(&dst, static_cast<int64_t>(1), static_cast<int64_t>(2), 2);
  EXPECT_THAT(dst, testing::ElementsAre(1, 2));
}

TEST(AddRangeTest, Advanced) {
  std::vector<int> dst;
  AddRange(&dst, 5, 15, 2);
  EXPECT_THAT(dst, testing::ElementsAre(5, 8, 15));
}

TEST(AddRangeTest, Advanced64) {
  std::vector<int64_t> dst;
  AddRange(&dst, static_cast<int64_t>(5), static_cast<int64_t>(15), 2);
  EXPECT_THAT(dst, testing::ElementsAre(5, 8, 15));
}

TEST(AddRangeTest, FullRange8) {
  std::vector<int8_t> dst;
  AddRange(&dst, int8_t{1}, std::numeric_limits<int8_t>::max(), 8);
  EXPECT_THAT(dst, testing::ElementsAre(1, 8, 64, 127));
}

TEST(AddRangeTest, FullRange64) {
  std::vector<int64_t> dst;
  AddRange(&dst, int64_t{1}, std::numeric_limits<int64_t>::max(), 1024);
  EXPECT_THAT(
      dst, testing::ElementsAre(1LL, 1024LL, 1048576LL, 1073741824LL,
                                1099511627776LL, 1125899906842624LL,
                                1152921504606846976LL, 9223372036854775807LL));
}

TEST(AddRangeTest, NegativeRanges) {
  std::vector<int> dst;
  AddRange(&dst, -8, 0, 2);
  EXPECT_THAT(dst, testing::ElementsAre(-8, -4, -2, -1, 0));
}

TEST(AddRangeTest, StrictlyNegative) {
  std::vector<int> dst;
  AddRange(&dst, -8, -1, 2);
  EXPECT_THAT(dst, testing::ElementsAre(-8, -4, -2, -1));
}

TEST(AddRangeTest, SymmetricNegativeRanges) {
  std::vector<int> dst;
  AddRange(&dst, -8, 8, 2);
  EXPECT_THAT(dst, testing::ElementsAre(-8, -4, -2, -1, 0, 1, 2, 4, 8));
}

TEST(AddRangeTest, SymmetricNegativeRangesOddMult) {
  std::vector<int> dst;
  AddRange(&dst, -30, 32, 5);
  EXPECT_THAT(dst, testing::ElementsAre(-30, -25, -5, -1, 0, 1, 5, 25, 32));
}

TEST(AddRangeTest, NegativeRangesAsymmetric) {
  std::vector<int> dst;
  AddRange(&dst, -3, 5, 2);
  EXPECT_THAT(dst, testing::ElementsAre(-3, -2, -1, 0, 1, 2, 4, 5));
}

TEST(AddRangeTest, NegativeRangesLargeStep) {
  // Always include -1, 0, 1 when crossing zero.
  std::vector<int> dst;
  AddRange(&dst, -8, 8, 10);
  EXPECT_THAT(dst, testing::ElementsAre(-8, -1, 0, 1, 8));
}

TEST(AddRangeTest, ZeroOnlyRange) {
  std::vector<int> dst;
  AddRange(&dst, 0, 0, 2);
  EXPECT_THAT(dst, testing::ElementsAre(0));
}

TEST(AddRangeTest, NegativeRange64) {
  std::vector<int64_t> dst;
  AddRange<int64_t>(&dst, -4, 4, 2);
  EXPECT_THAT(dst, testing::ElementsAre(-4, -2, -1, 0, 1, 2, 4));
}

TEST(AddRangeTest, NegativeRangePreservesExistingOrder) {
  // If elements already exist in the range, ensure we don't change
  // their ordering by adding negative values.
  std::vector<int64_t> dst = {1, 2, 3};
  AddRange<int64_t>(&dst, -2, 2, 2);
  EXPECT_THAT(dst, testing::ElementsAre(1, 2, 3, -2, -1, 0, 1, 2));
}

TEST(AddRangeTest, FullNegativeRange64) {
  std::vector<int64_t> dst;
  const auto min = std::numeric_limits<int64_t>::min();
  const auto max = std::numeric_limits<int64_t>::max();
  AddRange(&dst, min, max, 1024);
  EXPECT_THAT(
      dst, testing::ElementsAreArray(std::vector<int64_t>{
               min, -1152921504606846976LL, -1125899906842624LL,
               -1099511627776LL, -1073741824LL, -1048576LL, -1024LL, -1LL, 0LL,
               1LL, 1024LL, 1048576LL, 1073741824LL, 1099511627776LL,
               1125899906842624LL, 1152921504606846976LL, max}));
}

TEST(AddRangeTest, Simple8) {
  std::vector<int8_t> dst;
  AddRange<int8_t>(&dst, 1, 8, 2);
  EXPECT_THAT(dst, testing::ElementsAre(1, 2, 4, 8));
}

}  // namespace
}  // namespace internal
}  // namespace benchmark
