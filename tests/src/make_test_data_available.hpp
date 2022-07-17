#pragma once

#include <cstdio>   // fopen, fclose, FILE
#include <test_data.hpp>
#include <doctest.h>

namespace utils
{

inline bool check_testsuite_downloaded()
{
    std::FILE* file = std::fopen(TEST_DATA_DIRECTORY "/README.md", "r");
    if (!file)
    {
        return false;
    }
    std::fclose(file);
    return true;
}

TEST_CASE("check test suite is downloaded")
{
    REQUIRE_MESSAGE(utils::check_testsuite_downloaded(), "Test data not found in '" TEST_DATA_DIRECTORY "'. Please execute target 'download_test_data' before running this test suite. See <https://github.com/nlohmann/json#execute-unit-tests> for more information.");
}

}  // namespace utils
