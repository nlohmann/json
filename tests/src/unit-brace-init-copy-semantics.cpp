//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

// This file tests the opt-in JSON_BRACE_INIT_COPY_SEMANTICS, so it defines the
// macro itself rather than relying on a -D flag, and runs in every build.
#ifdef JSON_BRACE_INIT_COPY_SEMANTICS
    #undef JSON_BRACE_INIT_COPY_SEMANTICS
#endif

#define JSON_BRACE_INIT_COPY_SEMANTICS 1

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <array>
#include <list>
#include <map>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#define STRINGIZE_EX(x) #x
#define STRINGIZE(x) STRINGIZE_EX(x)

TEST_CASE("JSON_BRACE_INIT_COPY_SEMANTICS")
{
    SECTION("the macro is part of the ABI tag")
    {
        const std::string ns = STRINGIZE(NLOHMANN_JSON_NAMESPACE);
        // other tags may come before it, e.g. json_abi_ldvcmp_bics
        CHECK(ns.find("_bics") != std::string::npos);
    }

    SECTION("single-element brace initialization copies the element (#5074)")
    {
        json const j_obj = {{"key", "value"}, {"num", 42}};
        json const j_arr = {1, 2, 3};

        // object: brace init copies instead of wrapping
        json const j1{j_obj};
        CHECK(j1.is_object());
        CHECK(j1 == j_obj);

        // array: brace init copies instead of wrapping
        json const j2{j_arr};
        CHECK(j2.is_array());
        CHECK(j2.size() == 3);
        CHECK(j2 == j_arr);

        // this applies to any single element, not only to JSON values
        json const j3{true};
        CHECK(j3.is_boolean());

        json const j4{42};
        CHECK(j4.is_number_integer());

        json const j5 = {1};
        CHECK(j5 == 1);

        json const j6 = {"text"};
        CHECK(j6 == "text");

        json const j7 = {{1, 2}};
        CHECK(j7 == json::array({1, 2}));
    }

    SECTION("what the macro does not change")
    {
        // lists with more than one element are unaffected
        json const j1 = {1, 2};
        CHECK(j1.is_array());
        CHECK(j1.size() == 2);

        // a single [string, value] pair still describes an object
        json const j2 = {{"key", "value"}};
        CHECK(j2.is_object());
        CHECK(j2["key"] == "value");

        // json::array() always creates an array
        json const j3 = json::array({1});
        CHECK(j3.is_array());
        CHECK(j3.size() == 1);
        CHECK(j3[0] == 1);

        json const j_obj = {{"key", "value"}};
        json const j4 = json::array({j_obj});
        CHECK(j4.is_array());
        CHECK(j4.size() == 1);
        CHECK(j4[0] == j_obj);
    }

    SECTION("conversions build the same values as without the macro")
    {
        SECTION("one-element std::tuple")
        {
            json const j1 = std::tuple<int> {5};
            CHECK(j1.dump() == "[5]");
            CHECK(std::get<0>(j1.get<std::tuple<int>>()) == 5);

            json const j2 = std::tuple<std::string> {"text"};
            CHECK(j2.dump() == "[\"text\"]");
            CHECK(std::get<0>(j2.get<std::tuple<std::string>>()) == "text");

            json const j3 = std::tuple<json> {json::array({1, 2})};
            CHECK(j3.dump() == "[[1,2]]");

            // as without the macro, a [string, value] pair becomes an object
            // member (see the known limitation documented for std::pair)
            json const j4 = std::tuple<std::pair<std::string, int>> {{"a", 1}};
            CHECK(j4.dump() == "{\"a\":1}");
        }

        SECTION("tuples with more elements")
        {
            json const j1 = std::tuple<int, std::string> {1, "a"};
            CHECK(j1.dump() == "[1,\"a\"]");

            json const j2 = std::tuple<> {};
            CHECK(j2.dump() == "[]");
        }

        SECTION("one-element containers")
        {
            json const j1 = std::vector<int> {1};
            CHECK(j1.dump() == "[1]");
            CHECK(j1.get<std::vector<int>>() == std::vector<int> {1});

            std::array<int, 1> const arr = {{1}};
            json const j2 = arr;
            CHECK(j2.dump() == "[1]");

            json const j3 = std::list<std::string> {"a"};
            CHECK(j3.dump() == "[\"a\"]");

            json const j4 = std::map<std::string, int> {{"a", 1}};
            CHECK(j4.dump() == "{\"a\":1}");

            json const j5 = std::map<int, int> {{1, 2}};
            CHECK(j5.dump() == "[[1,2]]");
        }

        SECTION("std::pair")
        {
            json const j = std::pair<int, int> {1, 2};
            CHECK(j.dump() == "[1,2]");
            CHECK((j.get<std::pair<int, int>>() == std::pair<int, int> {1, 2}));
        }

        SECTION("items()")
        {
            json j_obj = {{"key", 1}};
            for (const auto& el : j_obj.items())
            {
                json const j = el;
                CHECK(j.dump() == "{\"key\":1}");
            }
        }
    }
}
