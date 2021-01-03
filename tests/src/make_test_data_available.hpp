//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.11.2
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2022 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdio>   // fopen, fclose, FILE
#include <memory> // unique_ptr
#include <test_data.hpp>
#include <doctest.h>

namespace utils
{

inline bool check_testsuite_downloaded()
{
    const std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(TEST_DATA_DIRECTORY "/README.md", "r"), &std::fclose);
    return file != nullptr;
}

TEST_CASE("check test suite is downloaded")
{
    REQUIRE_MESSAGE(utils::check_testsuite_downloaded(), "Test data not found in '" TEST_DATA_DIRECTORY "'. Please execute target 'download_test_data' before running this test suite. See <https://github.com/nlohmann/json#execute-unit-tests> for more information.");
}

}  // namespace utils
