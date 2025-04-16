//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013 - 2025 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#define JSON_TESTS_PRIVATE
#include <nlohmann/json.hpp>
using nlohmann::json;

TEST_CASE("iterators 1")
{
    SECTION("basic behavior")
    {
        SECTION("uninitialized")
        {
            json::iterator it;
            CHECK(it.m_object == nullptr);

            json::const_iterator cit;
            CHECK(cit.m_object == nullptr);
        }

        SECTION("boolean")
        {
            json j = true;
            json j_const(j);

            SECTION("json + begin/end")
            {
                json::iterator it = j.begin();
                CHECK(it != j.end());
                CHECK(*it == j);

                it++;
                CHECK(it != j.begin());
                CHECK(it == j.end());

                it--;
                CHECK(it == j.begin());
                CHECK(it != j.end());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.begin());
                CHECK(it == j.end());

                --it;
                CHECK(it == j.begin());
                CHECK(it != j.end());
                CHECK(*it == j);
            }

            SECTION("const json + begin/end")
            {
                json::const_iterator it = j_const.begin();
                CHECK(it != j_const.end());
                CHECK(*it == j_const);

                it++;
                CHECK(it != j_const.begin());
                CHECK(it == j_const.end());

                it--;
                CHECK(it == j_const.begin());
                CHECK(it != j_const.end());
                CHECK(*it == j_const);

                ++it;
                CHECK(it != j_const.begin());
                CHECK(it == j_const.end());

                --it;
                CHECK(it == j_const.begin());
                CHECK(it != j_const.end());
                CHECK(*it == j_const);
            }

            SECTION("json + cbegin/cend")
            {
                json::const_iterator it = j.cbegin();
                CHECK(it != j.cend());
                CHECK(*it == j);

                it++;
                CHECK(it != j.cbegin());
                CHECK(it == j.cend());

                it--;
                CHECK(it == j.cbegin());
                CHECK(it != j.cend());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.cbegin());
                CHECK(it == j.cend());

                --it;
                CHECK(it == j.cbegin());
                CHECK(it != j.cend());
                CHECK(*it == j);
            }

            SECTION("const json + cbegin/cend")
            {
                json::const_iterator it = j_const.cbegin();
                CHECK(it != j_const.cend());
                CHECK(*it == j_const);

                it++;
                CHECK(it != j_const.cbegin());
                CHECK(it == j_const.cend());

                it--;
                CHECK(it == j_const.cbegin());
                CHECK(it != j_const.cend());
                CHECK(*it == j_const);

                ++it;
                CHECK(it != j_const.cbegin());
                CHECK(it == j_const.cend());

                --it;
                CHECK(it == j_const.cbegin());
                CHECK(it != j_const.cend());
                CHECK(*it == j_const);
            }

            SECTION("json + rbegin/rend")
            {
                json::reverse_iterator it = j.rbegin();
                CHECK(it != j.rend());
                CHECK(*it == j);

                it++;
                CHECK(it != j.rbegin());
                CHECK(it == j.rend());

                it--;
                CHECK(it == j.rbegin());
                CHECK(it != j.rend());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.rbegin());
                CHECK(it == j.rend());

                --it;
                CHECK(it == j.rbegin());
                CHECK(it != j.rend());
                CHECK(*it == j);
            }

            SECTION("json + crbegin/crend")
            {
                json::const_reverse_iterator it = j.crbegin();
                CHECK(it != j.crend());
                CHECK(*it == j);

                it++;
                CHECK(it != j.crbegin());
                CHECK(it == j.crend());

                it--;
                CHECK(it == j.crbegin());
                CHECK(it != j.crend());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.crbegin());
                CHECK(it == j.crend());

                --it;
                CHECK(it == j.crbegin());
                CHECK(it != j.crend());
                CHECK(*it == j);
            }

            SECTION("const json + crbegin/crend")
            {
                json::const_reverse_iterator it = j_const.crbegin();
                CHECK(it != j_const.crend());
                CHECK(*it == j_const);

                it++;
                CHECK(it != j_const.crbegin());
                CHECK(it == j_const.crend());

                it--;
                CHECK(it == j_const.crbegin());
                CHECK(it != j_const.crend());
                CHECK(*it == j_const);

                ++it;
                CHECK(it != j_const.crbegin());
                CHECK(it == j_const.crend());

                --it;
                CHECK(it == j_const.crbegin());
                CHECK(it != j_const.crend());
                CHECK(*it == j_const);
            }

            SECTION("additional tests")
            {
                SECTION("!(begin != begin)")
                {
                    CHECK(!(j.begin() != j.begin()));
                }

                SECTION("!(end != end)")
                {
                    CHECK(!(j.end() != j.end()));
                }

                SECTION("begin < end")
                {
                    CHECK(j.begin() < j.end());
                }

                SECTION("begin <= end")
                {
                    CHECK(j.begin() <= j.end());
                }

                SECTION("end > begin")
                {
                    CHECK(j.end() > j.begin());
                }

                SECTION("end >= begin")
                {
                    CHECK(j.end() >= j.begin());
                }

                SECTION("end == end")
                {
                    CHECK(j.end() == j.end());
                }

                SECTION("end <= end")
                {
                    CHECK(j.end() <= j.end());
                }

                SECTION("begin == begin")
                {
                    CHECK(j.begin() == j.begin());
                }

                SECTION("begin <= begin")
                {
                    CHECK(j.begin() <= j.begin());
                }

                SECTION("begin >= begin")
                {
                    CHECK(j.begin() >= j.begin());
                }

                SECTION("!(begin == end)")
                {
                    CHECK(!(j.begin() == j.end()));
                }

                SECTION("begin != end")
                {
                    CHECK(j.begin() != j.end());
                }

                SECTION("begin+1 == end")
                {
                    CHECK(j.begin() + 1 == j.end());
                }

                SECTION("begin == end-1")
                {
                    CHECK(j.begin() == j.end() - 1);
                }

                SECTION("begin != end+1")
                {
                    CHECK(j.begin() != j.end() + 1);
                }

                SECTION("end != end+1")
                {
                    CHECK(j.end() != j.end() + 1);
                }

                SECTION("begin+1 != begin+2")
                {
                    CHECK(j.begin() + 1 != j.begin() + 2);
                }

                SECTION("begin+1 < begin+2")
                {
                    CHECK(j.begin() + 1 < j.begin() + 2);
                }

                SECTION("begin+1 <= begin+2")
                {
                    CHECK(j.begin() + 1 <= j.begin() + 2);
                }

                SECTION("end+1 != end+2")
                {
                    CHECK(j.end() + 1 != j.end() + 2);
                }
            }

            SECTION("key/value")
            {
                auto it = j.begin();
                auto cit = j_const.cbegin();
                CHECK_THROWS_WITH_AS(it.key(), "[json.exception.invalid_iterator.207] cannot use key() for non-object iterators", json::invalid_iterator&);
                CHECK(it.value() == json(true));
                CHECK_THROWS_WITH_AS(cit.key(), "[json.exception.invalid_iterator.207] cannot use key() for non-object iterators", json::invalid_iterator&);
                CHECK(cit.value() == json(true));

                auto rit = j.rend();
                auto crit = j.crend();
                CHECK_THROWS_WITH_AS(rit.key(), "[json.exception.invalid_iterator.207] cannot use key() for non-object iterators", json::invalid_iterator&);
                CHECK_THROWS_WITH_AS(rit.value(), "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
                CHECK_THROWS_WITH_AS(crit.key(), "[json.exception.invalid_iterator.207] cannot use key() for non-object iterators", json::invalid_iterator&);
                CHECK_THROWS_WITH_AS(crit.value(), "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
            }
        }

        SECTION("string")
        {
            json j = "hello world";
            json j_const(j);

            SECTION("json + begin/end")
            {
                json::iterator it = j.begin();
                CHECK(it != j.end());
                CHECK(*it == j);

                it++;
                CHECK(it != j.begin());
                CHECK(it == j.end());

                it--;
                CHECK(it == j.begin());
                CHECK(it != j.end());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.begin());
                CHECK(it == j.end());

                --it;
                CHECK(it == j.begin());
                CHECK(it != j.end());
                CHECK(*it == j);
            }

            SECTION("const json + begin/end")
            {
                json::const_iterator it = j_const.begin();
                CHECK(it != j_const.end());
                CHECK(*it == j_const);

                it++;
                CHECK(it != j_const.begin());
                CHECK(it == j_const.end());

                it--;
                CHECK(it == j_const.begin());
                CHECK(it != j_const.end());
                CHECK(*it == j_const);

                ++it;
                CHECK(it != j_const.begin());
                CHECK(it == j_const.end());

                --it;
                CHECK(it == j_const.begin());
                CHECK(it != j_const.end());
                CHECK(*it == j_const);
            }

            SECTION("json + cbegin/cend")
            {
                json::const_iterator it = j.cbegin();
                CHECK(it != j.cend());
                CHECK(*it == j);

                it++;
                CHECK(it != j.cbegin());
                CHECK(it == j.cend());

                it--;
                CHECK(it == j.cbegin());
                CHECK(it != j.cend());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.cbegin());
                CHECK(it == j.cend());

                --it;
                CHECK(it == j.cbegin());
                CHECK(it != j.cend());
                CHECK(*it == j);
            }

            SECTION("const json + cbegin/cend")
            {
                json::const_iterator it = j_const.cbegin();
                CHECK(it != j_const.cend());
                CHECK(*it == j_const);

                it++;
                CHECK(it != j_const.cbegin());
                CHECK(it == j_const.cend());

                it--;
                CHECK(it == j_const.cbegin());
                CHECK(it != j_const.cend());
                CHECK(*it == j_const);

                ++it;
                CHECK(it != j_const.cbegin());
                CHECK(it == j_const.cend());

                --it;
                CHECK(it == j_const.cbegin());
                CHECK(it != j_const.cend());
                CHECK(*it == j_const);
            }

            SECTION("json + rbegin/rend")
            {
                json::reverse_iterator it = j.rbegin();
                CHECK(it != j.rend());
                CHECK(*it == j);

                it++;
                CHECK(it != j.rbegin());
                CHECK(it == j.rend());

                it--;
                CHECK(it == j.rbegin());
                CHECK(it != j.rend());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.rbegin());
                CHECK(it == j.rend());

                --it;
                CHECK(it == j.rbegin());
                CHECK(it != j.rend());
                CHECK(*it == j);
            }

            SECTION("json + crbegin/crend")
            {
                json::const_reverse_iterator it = j.crbegin();
                CHECK(it != j.crend());
                CHECK(*it == j);

                it++;
                CHECK(it != j.crbegin());
                CHECK(it == j.crend());

                it--;
                CHECK(it == j.crbegin());
                CHECK(it != j.crend());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.crbegin());
                CHECK(it == j.crend());

                --it;
                CHECK(it == j.crbegin());
                CHECK(it != j.crend());
                CHECK(*it == j);
            }

            SECTION("const json + crbegin/crend")
            {
                json::const_reverse_iterator it = j_const.crbegin();
                CHECK(it != j_const.crend());
                CHECK(*it == j_const);

                it++;
                CHECK(it != j_const.crbegin());
                CHECK(it == j_const.crend());

                it--;
                CHECK(it == j_const.crbegin());
                CHECK(it != j_const.crend());
                CHECK(*it == j_const);

                ++it;
                CHECK(it != j_const.crbegin());
                CHECK(it == j_const.crend());

                --it;
                CHECK(it == j_const.crbegin());
                CHECK(it != j_const.crend());
                CHECK(*it == j_const);
            }

            SECTION("key/value")
            {
                auto it = j.begin();
                auto cit = j_const.cbegin();
                CHECK_THROWS_WITH_AS(it.key(), "[json.exception.invalid_iterator.207] cannot use key() for non-object iterators", json::invalid_iterator&);
                CHECK(it.value() == json("hello world"));
                CHECK_THROWS_WITH_AS(cit.key(), "[json.exception.invalid_iterator.207] cannot use key() for non-object iterators", json::invalid_iterator&);
                CHECK(cit.value() == json("hello world"));

                auto rit = j.rend();
                auto crit = j.crend();
                CHECK_THROWS_WITH_AS(rit.key(), "[json.exception.invalid_iterator.207] cannot use key() for non-object iterators", json::invalid_iterator&);
                CHECK_THROWS_WITH_AS(rit.value(), "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
                CHECK_THROWS_WITH_AS(crit.key(), "[json.exception.invalid_iterator.207] cannot use key() for non-object iterators", json::invalid_iterator&);
                CHECK_THROWS_WITH_AS(crit.value(), "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
            }
        }

        SECTION("array")
        {
            json j = {1, 2, 3};
            json j_const(j);

            SECTION("json + begin/end")
            {
                json::iterator it_begin = j.begin();
                json::iterator it_end = j.end();

                auto it = it_begin;
                CHECK(it != it_end);
                CHECK(*it == j[0]);

                it++;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j[1]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j[2]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it == it_end);
            }

            SECTION("const json + begin/end")
            {
                json::const_iterator it_begin = j_const.begin();
                json::const_iterator it_end = j_const.end();

                auto it = it_begin;
                CHECK(it != it_end);
                CHECK(*it == j_const[0]);

                it++;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j_const[1]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j_const[2]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it == it_end);
            }

            SECTION("json + cbegin/cend")
            {
                json::const_iterator it_begin = j.cbegin();
                json::const_iterator it_end = j.cend();

                auto it = it_begin;
                CHECK(it != it_end);
                CHECK(*it == j[0]);

                it++;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j[1]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j[2]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it == it_end);
            }

            SECTION("const json + cbegin/cend")
            {
                json::const_iterator it_begin = j_const.cbegin();
                json::const_iterator it_end = j_const.cend();

                auto it = it_begin;
                CHECK(it != it_end);
                CHECK(*it == j[0]);

                it++;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j[1]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j[2]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it == it_end);
            }

            SECTION("json + rbegin/rend")
            {
                json::reverse_iterator it_begin = j.rbegin();
                json::reverse_iterator it_end = j.rend();

                auto it = it_begin;
                CHECK(it != it_end);
                CHECK(*it == j[2]);

                it++;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j[1]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j[0]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it == it_end);
            }

            SECTION("json + crbegin/crend")
            {
                json::const_reverse_iterator it_begin = j.crbegin();
                json::const_reverse_iterator it_end = j.crend();

                auto it = it_begin;
                CHECK(it != it_end);
                CHECK(*it == j[2]);

                it++;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j[1]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j[0]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it == it_end);
            }

            SECTION("const json + crbegin/crend")
            {
                json::const_reverse_iterator it_begin = j_const.crbegin();
                json::const_reverse_iterator it_end = j_const.crend();

                auto it = it_begin;
                CHECK(it != it_end);
                CHECK(*it == j[2]);

                it++;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j[1]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j[0]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it == it_end);
            }

            SECTION("key/value")
            {
                auto it = j.begin();
                auto cit = j_const.cbegin();
                CHECK_THROWS_WITH_AS(it.key(), "[json.exception.invalid_iterator.207] cannot use key() for non-object iterators", json::invalid_iterator&);
                CHECK(it.value() == json(1));
                CHECK_THROWS_WITH_AS(cit.key(), "[json.exception.invalid_iterator.207] cannot use key() for non-object iterators", json::invalid_iterator&);
                CHECK(cit.value() == json(1));
            }
        }

        SECTION("object")
        {
            json j = {{"A", 1}, {"B", 2}, {"C", 3}};
            json j_const(j);

            SECTION("json + begin/end")
            {
                json::iterator it_begin = j.begin();
                json::iterator it_end = j.end();

                auto it = it_begin;
                CHECK(it != it_end);
                CHECK(*it == j["A"]);

                it++;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j["B"]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j["C"]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it == it_end);
            }

            SECTION("const json + begin/end")
            {
                json::const_iterator it_begin = j_const.begin();
                json::const_iterator it_end = j_const.end();

                auto it = it_begin;
                CHECK(it != it_end);
                CHECK(*it == j_const["A"]);

                it++;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j_const["B"]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j_const["C"]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it == it_end);
            }

            SECTION("json + cbegin/cend")
            {
                json::const_iterator it_begin = j.cbegin();
                json::const_iterator it_end = j.cend();

                auto it = it_begin;
                CHECK(it != it_end);
                CHECK(*it == j["A"]);

                it++;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j["B"]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j["C"]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it == it_end);
            }

            SECTION("const json + cbegin/cend")
            {
                json::const_iterator it_begin = j_const.cbegin();
                json::const_iterator it_end = j_const.cend();

                auto it = it_begin;
                CHECK(it != it_end);
                CHECK(*it == j_const["A"]);

                it++;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j_const["B"]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j_const["C"]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it == it_end);
            }

            SECTION("json + rbegin/rend")
            {
                json::reverse_iterator it_begin = j.rbegin();
                json::reverse_iterator it_end = j.rend();

                auto it = it_begin;
                CHECK(it != it_end);
                CHECK(*it == j["C"]);

                it++;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j["B"]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j["A"]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it == it_end);
            }

            SECTION("json + crbegin/crend")
            {
                json::const_reverse_iterator it_begin = j.crbegin();
                json::const_reverse_iterator it_end = j.crend();

                auto it = it_begin;
                CHECK(it != it_end);
                CHECK(*it == j["C"]);

                it++;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j["B"]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j["A"]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it == it_end);
            }

            SECTION("const json + crbegin/crend")
            {
                json::const_reverse_iterator it_begin = j_const.crbegin();
                json::const_reverse_iterator it_end = j_const.crend();

                auto it = it_begin;
                CHECK(it != it_end);
                CHECK(*it == j["C"]);

                it++;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j["B"]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it != it_end);
                CHECK(*it == j["A"]);

                ++it;
                CHECK(it != it_begin);
                CHECK(it == it_end);
            }

            SECTION("key/value")
            {
                auto it = j.begin();
                auto cit = j_const.cbegin();
                CHECK(it.key() == "A");
                CHECK(it.value() == json(1));
                CHECK(cit.key() == "A");
                CHECK(cit.value() == json(1));
            }
        }

        SECTION("number (integer)")
        {
            json j = 23;
            json j_const(j);

            SECTION("json + begin/end")
            {
                json::iterator it = j.begin();
                CHECK(it != j.end());
                CHECK(*it == j);

                it++;
                CHECK(it != j.begin());
                CHECK(it == j.end());

                it--;
                CHECK(it == j.begin());
                CHECK(it != j.end());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.begin());
                CHECK(it == j.end());

                --it;
                CHECK(it == j.begin());
                CHECK(it != j.end());
                CHECK(*it == j);
            }

            SECTION("const json + begin/end")
            {
                json::const_iterator it = j_const.begin();
                CHECK(it != j_const.end());
                CHECK(*it == j_const);

                it++;
                CHECK(it != j_const.begin());
                CHECK(it == j_const.end());

                it--;
                CHECK(it == j_const.begin());
                CHECK(it != j_const.end());
                CHECK(*it == j_const);

                ++it;
                CHECK(it != j_const.begin());
                CHECK(it == j_const.end());

                --it;
                CHECK(it == j_const.begin());
                CHECK(it != j_const.end());
                CHECK(*it == j_const);
            }

            SECTION("json + cbegin/cend")
            {
                json::const_iterator it = j.cbegin();
                CHECK(it != j.cend());
                CHECK(*it == j);

                it++;
                CHECK(it != j.cbegin());
                CHECK(it == j.cend());

                it--;
                CHECK(it == j.cbegin());
                CHECK(it != j.cend());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.cbegin());
                CHECK(it == j.cend());

                --it;
                CHECK(it == j.cbegin());
                CHECK(it != j.cend());
                CHECK(*it == j);
            }

            SECTION("const json + cbegin/cend")
            {
                json::const_iterator it = j_const.cbegin();
                CHECK(it != j_const.cend());
                CHECK(*it == j_const);

                it++;
                CHECK(it != j_const.cbegin());
                CHECK(it == j_const.cend());

                it--;
                CHECK(it == j_const.cbegin());
                CHECK(it != j_const.cend());
                CHECK(*it == j_const);

                ++it;
                CHECK(it != j_const.cbegin());
                CHECK(it == j_const.cend());

                --it;
                CHECK(it == j_const.cbegin());
                CHECK(it != j_const.cend());
                CHECK(*it == j_const);
            }

            SECTION("json + rbegin/rend")
            {
                json::reverse_iterator it = j.rbegin();
                CHECK(it != j.rend());
                CHECK(*it == j);

                it++;
                CHECK(it != j.rbegin());
                CHECK(it == j.rend());

                it--;
                CHECK(it == j.rbegin());
                CHECK(it != j.rend());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.rbegin());
                CHECK(it == j.rend());

                --it;
                CHECK(it == j.rbegin());
                CHECK(it != j.rend());
                CHECK(*it == j);
            }

            SECTION("json + crbegin/crend")
            {
                json::const_reverse_iterator it = j.crbegin();
                CHECK(it != j.crend());
                CHECK(*it == j);

                it++;
                CHECK(it != j.crbegin());
                CHECK(it == j.crend());

                it--;
                CHECK(it == j.crbegin());
                CHECK(it != j.crend());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.crbegin());
                CHECK(it == j.crend());

                --it;
                CHECK(it == j.crbegin());
                CHECK(it != j.crend());
                CHECK(*it == j);
            }

            SECTION("const json + crbegin/crend")
            {
                json::const_reverse_iterator it = j_const.crbegin();
                CHECK(it != j_const.crend());
                CHECK(*it == j_const);

                it++;
                CHECK(it != j_const.crbegin());
                CHECK(it == j_const.crend());

                it--;
                CHECK(it == j_const.crbegin());
                CHECK(it != j_const.crend());
                CHECK(*it == j_const);

                ++it;
                CHECK(it != j_const.crbegin());
                CHECK(it == j_const.crend());

                --it;
                CHECK(it == j_const.crbegin());
                CHECK(it != j_const.crend());
                CHECK(*it == j_const);
            }

            SECTION("key/value")
            {
                auto it = j.begin();
                auto cit = j_const.cbegin();
                CHECK_THROWS_WITH_AS(it.key(), "[json.exception.invalid_iterator.207] cannot use key() for non-object iterators", json::invalid_iterator&);
                CHECK(it.value() == json(23));
                CHECK_THROWS_WITH_AS(cit.key(), "[json.exception.invalid_iterator.207] cannot use key() for non-object iterators", json::invalid_iterator&);
                CHECK(cit.value() == json(23));

                auto rit = j.rend();
                auto crit = j.crend();
                CHECK_THROWS_WITH_AS(rit.key(), "[json.exception.invalid_iterator.207] cannot use key() for non-object iterators", json::invalid_iterator&);
                CHECK_THROWS_WITH_AS(rit.value(), "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
                CHECK_THROWS_WITH_AS(crit.key(), "[json.exception.invalid_iterator.207] cannot use key() for non-object iterators", json::invalid_iterator&);
                CHECK_THROWS_WITH_AS(crit.value(), "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
            }
        }

        SECTION("number (unsigned)")
        {
            json j = 23u;
            json j_const(j);

            SECTION("json + begin/end")
            {
                json::iterator it = j.begin();
                CHECK(it != j.end());
                CHECK(*it == j);

                it++;
                CHECK(it != j.begin());
                CHECK(it == j.end());

                it--;
                CHECK(it == j.begin());
                CHECK(it != j.end());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.begin());
                CHECK(it == j.end());

                --it;
                CHECK(it == j.begin());
                CHECK(it != j.end());
                CHECK(*it == j);
            }

            SECTION("const json + begin/end")
            {
                json::const_iterator it = j_const.begin();
                CHECK(it != j_const.end());
                CHECK(*it == j_const);

                it++;
                CHECK(it != j_const.begin());
                CHECK(it == j_const.end());

                it--;
                CHECK(it == j_const.begin());
                CHECK(it != j_const.end());
                CHECK(*it == j_const);

                ++it;
                CHECK(it != j_const.begin());
                CHECK(it == j_const.end());

                --it;
                CHECK(it == j_const.begin());
                CHECK(it != j_const.end());
                CHECK(*it == j_const);
            }

            SECTION("json + cbegin/cend")
            {
                json::const_iterator it = j.cbegin();
                CHECK(it != j.cend());
                CHECK(*it == j);

                it++;
                CHECK(it != j.cbegin());
                CHECK(it == j.cend());

                it--;
                CHECK(it == j.cbegin());
                CHECK(it != j.cend());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.cbegin());
                CHECK(it == j.cend());

                --it;
                CHECK(it == j.cbegin());
                CHECK(it != j.cend());
                CHECK(*it == j);
            }

            SECTION("const json + cbegin/cend")
            {
                json::const_iterator it = j_const.cbegin();
                CHECK(it != j_const.cend());
                CHECK(*it == j_const);

                it++;
                CHECK(it != j_const.cbegin());
                CHECK(it == j_const.cend());

                it--;
                CHECK(it == j_const.cbegin());
                CHECK(it != j_const.cend());
                CHECK(*it == j_const);

                ++it;
                CHECK(it != j_const.cbegin());
                CHECK(it == j_const.cend());

                --it;
                CHECK(it == j_const.cbegin());
                CHECK(it != j_const.cend());
                CHECK(*it == j_const);
            }

            SECTION("json + rbegin/rend")
            {
                json::reverse_iterator it = j.rbegin();
                CHECK(it != j.rend());
                CHECK(*it == j);

                it++;
                CHECK(it != j.rbegin());
                CHECK(it == j.rend());

                it--;
                CHECK(it == j.rbegin());
                CHECK(it != j.rend());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.rbegin());
                CHECK(it == j.rend());

                --it;
                CHECK(it == j.rbegin());
                CHECK(it != j.rend());
                CHECK(*it == j);
            }

            SECTION("json + crbegin/crend")
            {
                json::const_reverse_iterator it = j.crbegin();
                CHECK(it != j.crend());
                CHECK(*it == j);

                it++;
                CHECK(it != j.crbegin());
                CHECK(it == j.crend());

                it--;
                CHECK(it == j.crbegin());
                CHECK(it != j.crend());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.crbegin());
                CHECK(it == j.crend());

                --it;
                CHECK(it == j.crbegin());
                CHECK(it != j.crend());
                CHECK(*it == j);
            }

            SECTION("const json + crbegin/crend")
            {
                json::const_reverse_iterator it = j_const.crbegin();
                CHECK(it != j_const.crend());
                CHECK(*it == j_const);

                it++;
                CHECK(it != j_const.crbegin());
                CHECK(it == j_const.crend());

                it--;
                CHECK(it == j_const.crbegin());
                CHECK(it != j_const.crend());
                CHECK(*it == j_const);

                ++it;
                CHECK(it != j_const.crbegin());
                CHECK(it == j_const.crend());

                --it;
                CHECK(it == j_const.crbegin());
                CHECK(it != j_const.crend());
                CHECK(*it == j_const);
            }

            SECTION("key/value")
            {
                auto it = j.begin();
                auto cit = j_const.cbegin();
                CHECK_THROWS_WITH_AS(it.key(), "[json.exception.invalid_iterator.207] cannot use key() for non-object iterators", json::invalid_iterator&);
                CHECK(it.value() == json(23));
                CHECK_THROWS_WITH_AS(cit.key(), "[json.exception.invalid_iterator.207] cannot use key() for non-object iterators", json::invalid_iterator&);
                CHECK(cit.value() == json(23));

                auto rit = j.rend();
                auto crit = j.crend();
                CHECK_THROWS_WITH_AS(rit.key(), "[json.exception.invalid_iterator.207] cannot use key() for non-object iterators", json::invalid_iterator&);
                CHECK_THROWS_WITH_AS(rit.value(), "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
                CHECK_THROWS_WITH_AS(crit.key(), "[json.exception.invalid_iterator.207] cannot use key() for non-object iterators", json::invalid_iterator&);
                CHECK_THROWS_WITH_AS(crit.value(), "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
            }
        }

        SECTION("number (float)")
        {
            json j = 23.42;
            json j_const(j);

            SECTION("json + begin/end")
            {
                json::iterator it = j.begin();
                CHECK(it != j.end());
                CHECK(*it == j);

                it++;
                CHECK(it != j.begin());
                CHECK(it == j.end());

                it--;
                CHECK(it == j.begin());
                CHECK(it != j.end());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.begin());
                CHECK(it == j.end());

                --it;
                CHECK(it == j.begin());
                CHECK(it != j.end());
                CHECK(*it == j);
            }

            SECTION("const json + begin/end")
            {
                json::const_iterator it = j_const.begin();
                CHECK(it != j_const.end());
                CHECK(*it == j_const);

                it++;
                CHECK(it != j_const.begin());
                CHECK(it == j_const.end());

                it--;
                CHECK(it == j_const.begin());
                CHECK(it != j_const.end());
                CHECK(*it == j_const);

                ++it;
                CHECK(it != j_const.begin());
                CHECK(it == j_const.end());

                --it;
                CHECK(it == j_const.begin());
                CHECK(it != j_const.end());
                CHECK(*it == j_const);
            }

            SECTION("json + cbegin/cend")
            {
                json::const_iterator it = j.cbegin();
                CHECK(it != j.cend());
                CHECK(*it == j);

                it++;
                CHECK(it != j.cbegin());
                CHECK(it == j.cend());

                it--;
                CHECK(it == j.cbegin());
                CHECK(it != j.cend());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.cbegin());
                CHECK(it == j.cend());

                --it;
                CHECK(it == j.cbegin());
                CHECK(it != j.cend());
                CHECK(*it == j);
            }

            SECTION("const json + cbegin/cend")
            {
                json::const_iterator it = j_const.cbegin();
                CHECK(it != j_const.cend());
                CHECK(*it == j_const);

                it++;
                CHECK(it != j_const.cbegin());
                CHECK(it == j_const.cend());

                it--;
                CHECK(it == j_const.cbegin());
                CHECK(it != j_const.cend());
                CHECK(*it == j_const);

                ++it;
                CHECK(it != j_const.cbegin());
                CHECK(it == j_const.cend());

                --it;
                CHECK(it == j_const.cbegin());
                CHECK(it != j_const.cend());
                CHECK(*it == j_const);
            }

            SECTION("json + rbegin/rend")
            {
                json::reverse_iterator it = j.rbegin();
                CHECK(it != j.rend());
                CHECK(*it == j);

                it++;
                CHECK(it != j.rbegin());
                CHECK(it == j.rend());

                it--;
                CHECK(it == j.rbegin());
                CHECK(it != j.rend());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.rbegin());
                CHECK(it == j.rend());

                --it;
                CHECK(it == j.rbegin());
                CHECK(it != j.rend());
                CHECK(*it == j);
            }

            SECTION("json + crbegin/crend")
            {
                json::const_reverse_iterator it = j.crbegin();
                CHECK(it != j.crend());
                CHECK(*it == j);

                it++;
                CHECK(it != j.crbegin());
                CHECK(it == j.crend());

                it--;
                CHECK(it == j.crbegin());
                CHECK(it != j.crend());
                CHECK(*it == j);

                ++it;
                CHECK(it != j.crbegin());
                CHECK(it == j.crend());

                --it;
                CHECK(it == j.crbegin());
                CHECK(it != j.crend());
                CHECK(*it == j);
            }

            SECTION("const json + crbegin/crend")
            {
                json::const_reverse_iterator it = j_const.crbegin();
                CHECK(it != j_const.crend());
                CHECK(*it == j_const);

                it++;
                CHECK(it != j_const.crbegin());
                CHECK(it == j_const.crend());

                it--;
                CHECK(it == j_const.crbegin());
                CHECK(it != j_const.crend());
                CHECK(*it == j_const);

                ++it;
                CHECK(it != j_const.crbegin());
                CHECK(it == j_const.crend());

                --it;
                CHECK(it == j_const.crbegin());
                CHECK(it != j_const.crend());
                CHECK(*it == j_const);
            }

            SECTION("key/value")
            {
                auto it = j.begin();
                auto cit = j_const.cbegin();
                CHECK_THROWS_WITH_AS(it.key(), "[json.exception.invalid_iterator.207] cannot use key() for non-object iterators", json::invalid_iterator&);
                CHECK(it.value() == json(23.42));
                CHECK_THROWS_WITH_AS(cit.key(), "[json.exception.invalid_iterator.207] cannot use key() for non-object iterators", json::invalid_iterator&);
                CHECK(cit.value() == json(23.42));

                auto rit = j.rend();
                auto crit = j.crend();
                CHECK_THROWS_WITH_AS(rit.key(), "[json.exception.invalid_iterator.207] cannot use key() for non-object iterators", json::invalid_iterator&);
                CHECK_THROWS_WITH_AS(rit.value(), "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
                CHECK_THROWS_WITH_AS(crit.key(), "[json.exception.invalid_iterator.207] cannot use key() for non-object iterators", json::invalid_iterator&);
                CHECK_THROWS_WITH_AS(crit.value(), "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
            }
        }

        SECTION("null")
        {
            json j = nullptr;
            json j_const(j);

            SECTION("json + begin/end")
            {
                json::iterator it = j.begin();
                CHECK(it == j.end());
            }

            SECTION("const json + begin/end")
            {
                json::const_iterator it_begin = j_const.begin();
                json::const_iterator it_end = j_const.end();
                CHECK(it_begin == it_end);
            }

            SECTION("json + cbegin/cend")
            {
                json::const_iterator it_begin = j.cbegin();
                json::const_iterator it_end = j.cend();
                CHECK(it_begin == it_end);
            }

            SECTION("const json + cbegin/cend")
            {
                json::const_iterator it_begin = j_const.cbegin();
                json::const_iterator it_end = j_const.cend();
                CHECK(it_begin == it_end);
            }

            SECTION("json + rbegin/rend")
            {
                json::reverse_iterator it = j.rbegin();
                CHECK(it == j.rend());
            }

            SECTION("json + crbegin/crend")
            {
                json::const_reverse_iterator it = j.crbegin();
                CHECK(it == j.crend());
            }

            SECTION("const json + crbegin/crend")
            {
                json::const_reverse_iterator it = j_const.crbegin();
                CHECK(it == j_const.crend());
            }

            SECTION("key/value")
            {
                auto it = j.begin();
                auto cit = j_const.cbegin();
                CHECK_THROWS_WITH_AS(it.key(), "[json.exception.invalid_iterator.207] cannot use key() for non-object iterators", json::invalid_iterator&);
                CHECK_THROWS_WITH_AS(it.value(), "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
                CHECK_THROWS_WITH_AS(cit.key(), "[json.exception.invalid_iterator.207] cannot use key() for non-object iterators", json::invalid_iterator&);
                CHECK_THROWS_WITH_AS(cit.value(), "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);

                auto rit = j.rend();
                auto crit = j.crend();
                CHECK_THROWS_WITH_AS(rit.key(), "[json.exception.invalid_iterator.207] cannot use key() for non-object iterators", json::invalid_iterator&);
                CHECK_THROWS_WITH_AS(rit.value(), "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
                CHECK_THROWS_WITH_AS(crit.key(), "[json.exception.invalid_iterator.207] cannot use key() for non-object iterators", json::invalid_iterator&);
                CHECK_THROWS_WITH_AS(crit.value(), "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
            }
        }
    }

    SECTION("conversion from iterator to const iterator")
    {
        SECTION("boolean")
        {
            json j = true;
            json::const_iterator it = j.begin();
            CHECK(it == j.cbegin());
            it = j.begin();
            CHECK(it == j.cbegin());
        }
        SECTION("string")
        {
            json j = "hello world";
            json::const_iterator it = j.begin();
            CHECK(it == j.cbegin());
            it = j.begin();
            CHECK(it == j.cbegin());
        }
        SECTION("array")
        {
            json j = {1, 2, 3};
            json::const_iterator it = j.begin();
            CHECK(it == j.cbegin());
            it = j.begin();
            CHECK(it == j.cbegin());
        }
        SECTION("object")
        {
            json j = {{"A", 1}, {"B", 2}, {"C", 3}};
            json::const_iterator it = j.begin();
            CHECK(it == j.cbegin());
            it = j.begin();
            CHECK(it == j.cbegin());
        }
        SECTION("number (integer)")
        {
            json j = 23;
            json::const_iterator it = j.begin();
            CHECK(it == j.cbegin());
            it = j.begin();
            CHECK(it == j.cbegin());
        }
        SECTION("number (unsigned)")
        {
            json j = 23u;
            json::const_iterator it = j.begin();
            CHECK(it == j.cbegin());
            it = j.begin();
            CHECK(it == j.cbegin());
        }
        SECTION("number (float)")
        {
            json j = 23.42;
            json::const_iterator it = j.begin();
            CHECK(it == j.cbegin());
            it = j.begin();
            CHECK(it == j.cbegin());
        }
        SECTION("null")
        {
            json j = nullptr;
            json::const_iterator it = j.begin();
            CHECK(it == j.cbegin());
            it = j.begin();
            CHECK(it == j.cbegin());
        }
    }
}
