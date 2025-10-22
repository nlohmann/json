//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2025 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <string>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>
using nlohmann::json;

#if (defined(__cplusplus) && __cplusplus >= 201402L) || (defined(_HAS_CXX14) && _HAS_CXX14 == 1)
    #define JSON_HAS_CPP_14
#endif

#ifdef JSON_HAS_CPP_14
TEST_CASE_TEMPLATE("checking forward-iterators", T, // NOLINT(readability-math-missing-parentheses, bugprone-throwing-static-initialization)
                   std::vector<int>, std::string, nlohmann::json)
{
    auto it1 = typename T::iterator{};
    auto it2 = typename T::iterator{};
    CHECK(it1 == it2);
    CHECK(it1 <= it2);
    CHECK(it1 >= it2);
    CHECK_FALSE(it1 != it2);
    CHECK_FALSE(it1 < it2);
    CHECK_FALSE(it1 > it2);
}
#endif
