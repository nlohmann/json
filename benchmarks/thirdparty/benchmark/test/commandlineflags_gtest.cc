#include <cstdlib>

#include "../src/commandlineflags.h"
#include "../src/internal_macros.h"
#include "gtest/gtest.h"

namespace benchmark {
namespace {

#if defined(BENCHMARK_OS_WINDOWS)
int setenv(const char* name, const char* value, int overwrite) {
  if (!overwrite) {
    // NOTE: getenv_s is far superior but not available under mingw.
    char* env_value = getenv(name);
    if (env_value == nullptr) {
      return -1;
    }
  }
  return _putenv_s(name, value);
}

int unsetenv(const char* name) {
  return _putenv_s(name, "");
}

#endif  // BENCHMARK_OS_WINDOWS

TEST(BoolFromEnv, Default) {
  ASSERT_EQ(unsetenv("NOT_IN_ENV"), 0);
  EXPECT_EQ(BoolFromEnv("not_in_env", true), true);
}

TEST(BoolFromEnv, False) {
  ASSERT_EQ(setenv("IN_ENV", "0", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", true), false);
  unsetenv("IN_ENV");

  ASSERT_EQ(setenv("IN_ENV", "N", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", true), false);
  unsetenv("IN_ENV");

  ASSERT_EQ(setenv("IN_ENV", "n", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", true), false);
  unsetenv("IN_ENV");

  ASSERT_EQ(setenv("IN_ENV", "NO", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", true), false);
  unsetenv("IN_ENV");

  ASSERT_EQ(setenv("IN_ENV", "No", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", true), false);
  unsetenv("IN_ENV");

  ASSERT_EQ(setenv("IN_ENV", "no", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", true), false);
  unsetenv("IN_ENV");

  ASSERT_EQ(setenv("IN_ENV", "F", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", true), false);
  unsetenv("IN_ENV");

  ASSERT_EQ(setenv("IN_ENV", "f", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", true), false);
  unsetenv("IN_ENV");

  ASSERT_EQ(setenv("IN_ENV", "FALSE", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", true), false);
  unsetenv("IN_ENV");

  ASSERT_EQ(setenv("IN_ENV", "False", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", true), false);
  unsetenv("IN_ENV");

  ASSERT_EQ(setenv("IN_ENV", "false", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", true), false);
  unsetenv("IN_ENV");

  ASSERT_EQ(setenv("IN_ENV", "OFF", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", true), false);
  unsetenv("IN_ENV");

  ASSERT_EQ(setenv("IN_ENV", "Off", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", true), false);
  unsetenv("IN_ENV");

  ASSERT_EQ(setenv("IN_ENV", "off", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", true), false);
  unsetenv("IN_ENV");
}

TEST(BoolFromEnv, True) {
  ASSERT_EQ(setenv("IN_ENV", "1", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", false), true);
  unsetenv("IN_ENV");

  ASSERT_EQ(setenv("IN_ENV", "Y", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", false), true);
  unsetenv("IN_ENV");

  ASSERT_EQ(setenv("IN_ENV", "y", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", false), true);
  unsetenv("IN_ENV");

  ASSERT_EQ(setenv("IN_ENV", "YES", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", false), true);
  unsetenv("IN_ENV");

  ASSERT_EQ(setenv("IN_ENV", "Yes", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", false), true);
  unsetenv("IN_ENV");

  ASSERT_EQ(setenv("IN_ENV", "yes", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", false), true);
  unsetenv("IN_ENV");

  ASSERT_EQ(setenv("IN_ENV", "T", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", false), true);
  unsetenv("IN_ENV");

  ASSERT_EQ(setenv("IN_ENV", "t", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", false), true);
  unsetenv("IN_ENV");

  ASSERT_EQ(setenv("IN_ENV", "TRUE", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", false), true);
  unsetenv("IN_ENV");

  ASSERT_EQ(setenv("IN_ENV", "True", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", false), true);
  unsetenv("IN_ENV");

  ASSERT_EQ(setenv("IN_ENV", "true", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", false), true);
  unsetenv("IN_ENV");

  ASSERT_EQ(setenv("IN_ENV", "ON", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", false), true);
  unsetenv("IN_ENV");

  ASSERT_EQ(setenv("IN_ENV", "On", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", false), true);
  unsetenv("IN_ENV");

  ASSERT_EQ(setenv("IN_ENV", "on", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", false), true);
  unsetenv("IN_ENV");

#ifndef BENCHMARK_OS_WINDOWS
  ASSERT_EQ(setenv("IN_ENV", "", 1), 0);
  EXPECT_EQ(BoolFromEnv("in_env", false), true);
  unsetenv("IN_ENV");
#endif
}

TEST(Int32FromEnv, NotInEnv) {
  ASSERT_EQ(unsetenv("NOT_IN_ENV"), 0);
  EXPECT_EQ(Int32FromEnv("not_in_env", 42), 42);
}

TEST(Int32FromEnv, InvalidInteger) {
  ASSERT_EQ(setenv("IN_ENV", "foo", 1), 0);
  EXPECT_EQ(Int32FromEnv("in_env", 42), 42);
  unsetenv("IN_ENV");
}

TEST(Int32FromEnv, ValidInteger) {
  ASSERT_EQ(setenv("IN_ENV", "42", 1), 0);
  EXPECT_EQ(Int32FromEnv("in_env", 64), 42);
  unsetenv("IN_ENV");
}

TEST(DoubleFromEnv, NotInEnv) {
  ASSERT_EQ(unsetenv("NOT_IN_ENV"), 0);
  EXPECT_EQ(DoubleFromEnv("not_in_env", 0.51), 0.51);
}

TEST(DoubleFromEnv, InvalidReal) {
  ASSERT_EQ(setenv("IN_ENV", "foo", 1), 0);
  EXPECT_EQ(DoubleFromEnv("in_env", 0.51), 0.51);
  unsetenv("IN_ENV");
}

TEST(DoubleFromEnv, ValidReal) {
  ASSERT_EQ(setenv("IN_ENV", "0.51", 1), 0);
  EXPECT_EQ(DoubleFromEnv("in_env", 0.71), 0.51);
  unsetenv("IN_ENV");
}

TEST(StringFromEnv, Default) {
  ASSERT_EQ(unsetenv("NOT_IN_ENV"), 0);
  EXPECT_STREQ(StringFromEnv("not_in_env", "foo"), "foo");
}

TEST(StringFromEnv, Valid) {
  ASSERT_EQ(setenv("IN_ENV", "foo", 1), 0);
  EXPECT_STREQ(StringFromEnv("in_env", "bar"), "foo");
  unsetenv("IN_ENV");
}

}  // namespace
}  // namespace benchmark
