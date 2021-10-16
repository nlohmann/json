/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.10.4
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
SPDX-License-Identifier: MIT
Copyright (c) 2013-2019 Niels Lohmann <http://nlohmann.me>.

Permission is hereby  granted, free of charge, to any  person obtaining a copy
of this software and associated  documentation files (the "Software"), to deal
in the Software  without restriction, including without  limitation the rights
to  use, copy,  modify, merge,  publish, distribute,  sublicense, and/or  sell
copies  of  the Software,  and  to  permit persons  to  whom  the Software  is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE  IS PROVIDED "AS  IS", WITHOUT WARRANTY  OF ANY KIND,  EXPRESS OR
IMPLIED,  INCLUDING BUT  NOT  LIMITED TO  THE  WARRANTIES OF  MERCHANTABILITY,
FITNESS FOR  A PARTICULAR PURPOSE AND  NONINFRINGEMENT. IN NO EVENT  SHALL THE
AUTHORS  OR COPYRIGHT  HOLDERS  BE  LIABLE FOR  ANY  CLAIM,  DAMAGES OR  OTHER
LIABILITY, WHETHER IN AN ACTION OF  CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE  OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

TEST_CASE("iterators 2")
{
    SECTION("iterator comparisons")
    {
        json j_values = {nullptr, true, 42, 42u, 23.23, {{"one", 1}, {"two", 2}}, {1, 2, 3, 4, 5}, "Hello, world"};

        for (json& j : j_values)
        {
            auto it1 = j.begin();
            auto it2 = j.begin();
            auto it3 = j.begin();
            ++it2;
            ++it3;
            ++it3;
            auto it1_c = j.cbegin();
            auto it2_c = j.cbegin();
            auto it3_c = j.cbegin();
            ++it2_c;
            ++it3_c;
            ++it3_c;

            // comparison: equal
            {
                CHECK(it1 == it1);
                CHECK(!(it1 == it2));
                CHECK(!(it1 == it3));
                CHECK(!(it2 == it3));
                CHECK(it1_c == it1_c);
                CHECK(!(it1_c == it2_c));
                CHECK(!(it1_c == it3_c));
                CHECK(!(it2_c == it3_c));
            }

            // comparison: not equal
            {
                // check definition
                CHECK( (it1 != it1) == !(it1 == it1) );
                CHECK( (it1 != it2) == !(it1 == it2) );
                CHECK( (it1 != it3) == !(it1 == it3) );
                CHECK( (it2 != it3) == !(it2 == it3) );
                CHECK( (it1_c != it1_c) == !(it1_c == it1_c) );
                CHECK( (it1_c != it2_c) == !(it1_c == it2_c) );
                CHECK( (it1_c != it3_c) == !(it1_c == it3_c) );
                CHECK( (it2_c != it3_c) == !(it2_c == it3_c) );
            }

            // comparison: smaller
            {
                if (j.type() == json::value_t::object)
                {
                    CHECK_THROWS_AS(it1 < it1, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1 < it2, json::invalid_iterator&);
                    CHECK_THROWS_AS(it2 < it3, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1 < it3, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1_c < it1_c, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1_c < it2_c, json::invalid_iterator&);
                    CHECK_THROWS_AS(it2_c < it3_c, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1_c < it3_c, json::invalid_iterator&);
#if JSON_DIAGNOSTICS
                    CHECK_THROWS_WITH(it1 < it1, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 < it2, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2 < it3, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 < it3, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c < it1_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c < it2_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2_c < it3_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c < it3_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
#else
                    CHECK_THROWS_WITH(it1 < it1, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 < it2, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2 < it3, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 < it3, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c < it1_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c < it2_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2_c < it3_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c < it3_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
#endif
                }
                else
                {
                    CHECK(!(it1 < it1));
                    CHECK(it1 < it2);
                    CHECK(it1 < it3);
                    CHECK(it2 < it3);
                    CHECK(!(it1_c < it1_c));
                    CHECK(it1_c < it2_c);
                    CHECK(it1_c < it3_c);
                    CHECK(it2_c < it3_c);
                }
            }

            // comparison: less than or equal
            {
                if (j.type() == json::value_t::object)
                {
                    CHECK_THROWS_AS(it1 <= it1, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1 <= it2, json::invalid_iterator&);
                    CHECK_THROWS_AS(it2 <= it3, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1 <= it3, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1_c <= it1_c, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1_c <= it2_c, json::invalid_iterator&);
                    CHECK_THROWS_AS(it2_c <= it3_c, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1_c <= it3_c, json::invalid_iterator&);
#if JSON_DIAGNOSTICS
                    CHECK_THROWS_WITH(it1 <= it1, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 <= it2, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2 <= it3, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 <= it3, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c <= it1_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c <= it2_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2_c <= it3_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c <= it3_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
#else
                    CHECK_THROWS_WITH(it1 <= it1, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 <= it2, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2 <= it3, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 <= it3, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c <= it1_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c <= it2_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2_c <= it3_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c <= it3_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
#endif
                }
                else
                {
                    // check definition
                    CHECK( (it1 <= it1) == !(it1 < it1) );
                    CHECK( (it1 <= it2) == !(it2 < it1) );
                    CHECK( (it1 <= it3) == !(it3 < it1) );
                    CHECK( (it2 <= it3) == !(it3 < it2) );
                    CHECK( (it1_c <= it1_c) == !(it1_c < it1_c) );
                    CHECK( (it1_c <= it2_c) == !(it2_c < it1_c) );
                    CHECK( (it1_c <= it3_c) == !(it3_c < it1_c) );
                    CHECK( (it2_c <= it3_c) == !(it3_c < it2_c) );
                }
            }

            // comparison: greater than
            {
                if (j.type() == json::value_t::object)
                {
                    CHECK_THROWS_AS(it1 > it1, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1 > it2, json::invalid_iterator&);
                    CHECK_THROWS_AS(it2 > it3, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1 > it3, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1_c > it1_c, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1_c > it2_c, json::invalid_iterator&);
                    CHECK_THROWS_AS(it2_c > it3_c, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1_c > it3_c, json::invalid_iterator&);
#if JSON_DIAGNOSTICS
                    CHECK_THROWS_WITH(it1 > it1, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 > it2, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2 > it3, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 > it3, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c > it1_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c > it2_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2_c > it3_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c > it3_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
#else
                    CHECK_THROWS_WITH(it1 > it1, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 > it2, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2 > it3, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 > it3, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c > it1_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c > it2_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2_c > it3_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c > it3_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
#endif
                }
                else
                {
                    // check definition
                    CHECK( (it1 > it1) == (it1 < it1) );
                    CHECK( (it1 > it2) == (it2 < it1) );
                    CHECK( (it1 > it3) == (it3 < it1) );
                    CHECK( (it2 > it3) == (it3 < it2) );
                    CHECK( (it1_c > it1_c) == (it1_c < it1_c) );
                    CHECK( (it1_c > it2_c) == (it2_c < it1_c) );
                    CHECK( (it1_c > it3_c) == (it3_c < it1_c) );
                    CHECK( (it2_c > it3_c) == (it3_c < it2_c) );
                }
            }

            // comparison: greater than or equal
            {
                if (j.type() == json::value_t::object)
                {
                    CHECK_THROWS_AS(it1 >= it1, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1 >= it2, json::invalid_iterator&);
                    CHECK_THROWS_AS(it2 >= it3, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1 >= it3, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1_c >= it1_c, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1_c >= it2_c, json::invalid_iterator&);
                    CHECK_THROWS_AS(it2_c >= it3_c, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1_c >= it3_c, json::invalid_iterator&);
#if JSON_DIAGNOSTICS
                    CHECK_THROWS_WITH(it1 >= it1, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 >= it2, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2 >= it3, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 >= it3, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c >= it1_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c >= it2_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2_c >= it3_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c >= it3_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
#else
                    CHECK_THROWS_WITH(it1 >= it1, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 >= it2, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2 >= it3, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 >= it3, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c >= it1_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c >= it2_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2_c >= it3_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c >= it3_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
#endif
                }
                else
                {
                    // check definition
                    CHECK( (it1 >= it1) == !(it1 < it1) );
                    CHECK( (it1 >= it2) == !(it1 < it2) );
                    CHECK( (it1 >= it3) == !(it1 < it3) );
                    CHECK( (it2 >= it3) == !(it2 < it3) );
                    CHECK( (it1_c >= it1_c) == !(it1_c < it1_c) );
                    CHECK( (it1_c >= it2_c) == !(it1_c < it2_c) );
                    CHECK( (it1_c >= it3_c) == !(it1_c < it3_c) );
                    CHECK( (it2_c >= it3_c) == !(it2_c < it3_c) );
                }
            }
        }

        // check exceptions if different objects are compared
        for (auto j : j_values)
        {
            for (auto k : j_values)
            {
                if (j != k)
                {
                    CHECK_THROWS_AS(j.begin() == k.begin(), json::invalid_iterator&);
                    CHECK_THROWS_AS(j.cbegin() == k.cbegin(), json::invalid_iterator&);
                    CHECK_THROWS_AS(j.begin() < k.begin(), json::invalid_iterator&);
                    CHECK_THROWS_AS(j.cbegin() < k.cbegin(), json::invalid_iterator&);
#if JSON_DIAGNOSTICS
                    // the output differs in each loop, so we cannot fix a string for the expected exception
#else
                    CHECK_THROWS_WITH(j.begin() == k.begin(), "[json.exception.invalid_iterator.212] cannot compare iterators of different containers");
                    CHECK_THROWS_WITH(j.cbegin() == k.cbegin(), "[json.exception.invalid_iterator.212] cannot compare iterators of different containers");
                    CHECK_THROWS_WITH(j.begin() < k.begin(), "[json.exception.invalid_iterator.212] cannot compare iterators of different containers");
                    CHECK_THROWS_WITH(j.cbegin() < k.cbegin(), "[json.exception.invalid_iterator.212] cannot compare iterators of different containers");
#endif
                }
            }
        }
    }

    SECTION("iterator arithmetic")
    {
        json j_object = {{"one", 1}, {"two", 2}, {"three", 3}};
        json j_array = {1, 2, 3, 4, 5, 6};
        json j_null = nullptr;
        json j_value = 42;

        SECTION("addition and subtraction")
        {
            SECTION("object")
            {
                {
                    auto it = j_object.begin();
                    CHECK_THROWS_AS(it += 1, json::invalid_iterator&);
                    CHECK_THROWS_WITH(it += 1, "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
                }
                {
                    auto it = j_object.cbegin();
                    CHECK_THROWS_AS(it += 1, json::invalid_iterator&);
                    CHECK_THROWS_WITH(it += 1, "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
                }
                {
                    auto it = j_object.begin();
                    CHECK_THROWS_AS(it + 1, json::invalid_iterator&);
                    CHECK_THROWS_WITH(it + 1, "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
                }
                {
                    auto it = j_object.cbegin();
                    CHECK_THROWS_AS(it + 1, json::invalid_iterator&);
                    CHECK_THROWS_WITH(it + 1, "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
                }
                {
                    auto it = j_object.begin();
                    CHECK_THROWS_AS(1 + it, json::invalid_iterator&);
                    CHECK_THROWS_WITH(1 + it, "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
                }
                {
                    auto it = j_object.cbegin();
                    CHECK_THROWS_AS(1 + it, json::invalid_iterator&);
                    CHECK_THROWS_WITH(1 + it, "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
                }
                {
                    auto it = j_object.begin();
                    CHECK_THROWS_AS(it -= 1, json::invalid_iterator&);
                    CHECK_THROWS_WITH(it -= 1, "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
                }
                {
                    auto it = j_object.cbegin();
                    CHECK_THROWS_AS(it -= 1, json::invalid_iterator&);
                    CHECK_THROWS_WITH(it -= 1, "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
                }
                {
                    auto it = j_object.begin();
                    CHECK_THROWS_AS(it - 1, json::invalid_iterator&);
                    CHECK_THROWS_WITH(it - 1, "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
                }
                {
                    auto it = j_object.cbegin();
                    CHECK_THROWS_AS(it - 1, json::invalid_iterator&);
                    CHECK_THROWS_WITH(it - 1, "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
                }
                {
                    auto it = j_object.begin();
                    CHECK_THROWS_AS(it - it, json::invalid_iterator&);
                    CHECK_THROWS_WITH(it - it, "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
                }
                {
                    auto it = j_object.cbegin();
                    CHECK_THROWS_AS(it - it, json::invalid_iterator&);
                    CHECK_THROWS_WITH(it - it, "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
                }
            }

            SECTION("array")
            {
                {
                    auto it = j_array.begin();
                    it += 3;
                    CHECK((j_array.begin() + 3) == it);
                    CHECK((3 + j_array.begin()) == it);
                    CHECK((it - 3) == j_array.begin());
                    CHECK((it - j_array.begin()) == 3);
                    CHECK(*it == json(4));
                    it -= 2;
                    CHECK(*it == json(2));
                }
                {
                    auto it = j_array.cbegin();
                    it += 3;
                    CHECK((j_array.cbegin() + 3) == it);
                    CHECK((3 + j_array.cbegin()) == it);
                    CHECK((it - 3) == j_array.cbegin());
                    CHECK((it - j_array.cbegin()) == 3);
                    CHECK(*it == json(4));
                    it -= 2;
                    CHECK(*it == json(2));
                }
            }

            SECTION("null")
            {
                {
                    auto it = j_null.begin();
                    it += 3;
                    CHECK((j_null.begin() + 3) == it);
                    CHECK((3 + j_null.begin()) == it);
                    CHECK((it - 3) == j_null.begin());
                    CHECK((it - j_null.begin()) == 3);
                    CHECK(it != j_null.end());
                    it -= 3;
                    CHECK(it == j_null.end());
                }
                {
                    auto it = j_null.cbegin();
                    it += 3;
                    CHECK((j_null.cbegin() + 3) == it);
                    CHECK((3 + j_null.cbegin()) == it);
                    CHECK((it - 3) == j_null.cbegin());
                    CHECK((it - j_null.cbegin()) == 3);
                    CHECK(it != j_null.cend());
                    it -= 3;
                    CHECK(it == j_null.cend());
                }
            }

            SECTION("value")
            {
                {
                    auto it = j_value.begin();
                    it += 3;
                    CHECK((j_value.begin() + 3) == it);
                    CHECK((3 + j_value.begin()) == it);
                    CHECK((it - 3) == j_value.begin());
                    CHECK((it - j_value.begin()) == 3);
                    CHECK(it != j_value.end());
                    it -= 3;
                    CHECK(*it == json(42));
                }
                {
                    auto it = j_value.cbegin();
                    it += 3;
                    CHECK((j_value.cbegin() + 3) == it);
                    CHECK((3 + j_value.cbegin()) == it);
                    CHECK((it - 3) == j_value.cbegin());
                    CHECK((it - j_value.cbegin()) == 3);
                    CHECK(it != j_value.cend());
                    it -= 3;
                    CHECK(*it == json(42));
                }
            }
        }

        SECTION("subscript operator")
        {
            SECTION("object")
            {
                {
                    auto it = j_object.begin();
                    CHECK_THROWS_AS(it[0], json::invalid_iterator&);
                    CHECK_THROWS_AS(it[1], json::invalid_iterator&);
                    CHECK_THROWS_WITH(it[0], "[json.exception.invalid_iterator.208] cannot use operator[] for object iterators");
                    CHECK_THROWS_WITH(it[1], "[json.exception.invalid_iterator.208] cannot use operator[] for object iterators");
                }
                {
                    auto it = j_object.cbegin();
                    CHECK_THROWS_AS(it[0], json::invalid_iterator&);
                    CHECK_THROWS_AS(it[1], json::invalid_iterator&);
                    CHECK_THROWS_WITH(it[0], "[json.exception.invalid_iterator.208] cannot use operator[] for object iterators");
                    CHECK_THROWS_WITH(it[1], "[json.exception.invalid_iterator.208] cannot use operator[] for object iterators");
                }
            }

            SECTION("array")
            {
                {
                    auto it = j_array.begin();
                    CHECK(it[0] == json(1));
                    CHECK(it[1] == json(2));
                    CHECK(it[2] == json(3));
                    CHECK(it[3] == json(4));
                    CHECK(it[4] == json(5));
                    CHECK(it[5] == json(6));
                }
                {
                    auto it = j_array.cbegin();
                    CHECK(it[0] == json(1));
                    CHECK(it[1] == json(2));
                    CHECK(it[2] == json(3));
                    CHECK(it[3] == json(4));
                    CHECK(it[4] == json(5));
                    CHECK(it[5] == json(6));
                }
            }

            SECTION("null")
            {
                {
                    auto it = j_null.begin();
                    CHECK_THROWS_AS(it[0], json::invalid_iterator&);
                    CHECK_THROWS_AS(it[1], json::invalid_iterator&);
                    CHECK_THROWS_WITH(it[0], "[json.exception.invalid_iterator.214] cannot get value");
                    CHECK_THROWS_WITH(it[1], "[json.exception.invalid_iterator.214] cannot get value");
                }
                {
                    auto it = j_null.cbegin();
                    CHECK_THROWS_AS(it[0], json::invalid_iterator&);
                    CHECK_THROWS_AS(it[1], json::invalid_iterator&);
                    CHECK_THROWS_WITH(it[0], "[json.exception.invalid_iterator.214] cannot get value");
                    CHECK_THROWS_WITH(it[1], "[json.exception.invalid_iterator.214] cannot get value");
                }
            }

            SECTION("value")
            {
                {
                    auto it = j_value.begin();
                    CHECK(it[0] == json(42));
                    CHECK_THROWS_AS(it[1], json::invalid_iterator&);
                    CHECK_THROWS_WITH(it[1], "[json.exception.invalid_iterator.214] cannot get value");
                }
                {
                    auto it = j_value.cbegin();
                    CHECK(it[0] == json(42));
                    CHECK_THROWS_AS(it[1], json::invalid_iterator&);
                    CHECK_THROWS_WITH(it[1], "[json.exception.invalid_iterator.214] cannot get value");
                }
            }
        }
    }

    SECTION("reverse iterator comparisons")
    {
        json j_values = {nullptr, true, 42, 42u, 23.23, {{"one", 1}, {"two", 2}}, {1, 2, 3, 4, 5}, "Hello, world"};

        for (json& j : j_values)
        {
            auto it1 = j.rbegin();
            auto it2 = j.rbegin();
            auto it3 = j.rbegin();
            ++it2;
            ++it3;
            ++it3;
            auto it1_c = j.crbegin();
            auto it2_c = j.crbegin();
            auto it3_c = j.crbegin();
            ++it2_c;
            ++it3_c;
            ++it3_c;

            // comparison: equal
            {
                CHECK(it1 == it1);
                CHECK(!(it1 == it2));
                CHECK(!(it1 == it3));
                CHECK(!(it2 == it3));
                CHECK(it1_c == it1_c);
                CHECK(!(it1_c == it2_c));
                CHECK(!(it1_c == it3_c));
                CHECK(!(it2_c == it3_c));
            }

            // comparison: not equal
            {
                // check definition
                CHECK( (it1 != it1) == !(it1 == it1) );
                CHECK( (it1 != it2) == !(it1 == it2) );
                CHECK( (it1 != it3) == !(it1 == it3) );
                CHECK( (it2 != it3) == !(it2 == it3) );
                CHECK( (it1_c != it1_c) == !(it1_c == it1_c) );
                CHECK( (it1_c != it2_c) == !(it1_c == it2_c) );
                CHECK( (it1_c != it3_c) == !(it1_c == it3_c) );
                CHECK( (it2_c != it3_c) == !(it2_c == it3_c) );
            }

            // comparison: smaller
            {
                if (j.type() == json::value_t::object)
                {
                    CHECK_THROWS_AS(it1 < it1, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1 < it2, json::invalid_iterator&);
                    CHECK_THROWS_AS(it2 < it3, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1 < it3, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1_c < it1_c, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1_c < it2_c, json::invalid_iterator&);
                    CHECK_THROWS_AS(it2_c < it3_c, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1_c < it3_c, json::invalid_iterator&);
#if JSON_DIAGNOSTICS
                    CHECK_THROWS_WITH(it1 < it1, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 < it2, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2 < it3, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 < it3, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c < it1_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c < it2_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2_c < it3_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c < it3_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
#else
                    CHECK_THROWS_WITH(it1 < it1, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 < it2, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2 < it3, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 < it3, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c < it1_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c < it2_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2_c < it3_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c < it3_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
#endif
                }
                else
                {
                    CHECK(!(it1 < it1));
                    CHECK(it1 < it2);
                    CHECK(it1 < it3);
                    CHECK(it2 < it3);
                    CHECK(!(it1_c < it1_c));
                    CHECK(it1_c < it2_c);
                    CHECK(it1_c < it3_c);
                    CHECK(it2_c < it3_c);
                }
            }

            // comparison: less than or equal
            {
                if (j.type() == json::value_t::object)
                {
                    CHECK_THROWS_AS(it1 <= it1, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1 <= it2, json::invalid_iterator&);
                    CHECK_THROWS_AS(it2 <= it3, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1 <= it3, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1_c <= it1_c, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1_c <= it2_c, json::invalid_iterator&);
                    CHECK_THROWS_AS(it2_c <= it3_c, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1_c <= it3_c, json::invalid_iterator&);
#if JSON_DIAGNOSTICS
                    CHECK_THROWS_WITH(it1 <= it1, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 <= it2, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2 <= it3, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 <= it3, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c <= it1_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c <= it2_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2_c <= it3_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c <= it3_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
#else
                    CHECK_THROWS_WITH(it1 <= it1, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 <= it2, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2 <= it3, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 <= it3, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c <= it1_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c <= it2_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2_c <= it3_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c <= it3_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
#endif
                }
                else
                {
                    // check definition
                    CHECK( (it1 <= it1) == !(it1 < it1) );
                    CHECK( (it1 <= it2) == !(it2 < it1) );
                    CHECK( (it1 <= it3) == !(it3 < it1) );
                    CHECK( (it2 <= it3) == !(it3 < it2) );
                    CHECK( (it1_c <= it1_c) == !(it1_c < it1_c) );
                    CHECK( (it1_c <= it2_c) == !(it2_c < it1_c) );
                    CHECK( (it1_c <= it3_c) == !(it3_c < it1_c) );
                    CHECK( (it2_c <= it3_c) == !(it3_c < it2_c) );
                }
            }

            // comparison: greater than
            {
                if (j.type() == json::value_t::object)
                {
                    CHECK_THROWS_AS(it1 > it1, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1 > it2, json::invalid_iterator&);
                    CHECK_THROWS_AS(it2 > it3, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1 > it3, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1_c > it1_c, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1_c > it2_c, json::invalid_iterator&);
                    CHECK_THROWS_AS(it2_c > it3_c, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1_c > it3_c, json::invalid_iterator&);
#if JSON_DIAGNOSTICS
                    CHECK_THROWS_WITH(it1 > it1, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 > it2, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2 > it3, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 > it3, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c > it1_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c > it2_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2_c > it3_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c > it3_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
#else
                    CHECK_THROWS_WITH(it1 > it1, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 > it2, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2 > it3, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 > it3, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c > it1_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c > it2_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2_c > it3_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c > it3_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
#endif
                }
                else
                {
                    // check definition
                    CHECK( (it1 > it1) == (it1 < it1) );
                    CHECK( (it1 > it2) == (it2 < it1) );
                    CHECK( (it1 > it3) == (it3 < it1) );
                    CHECK( (it2 > it3) == (it3 < it2) );
                    CHECK( (it1_c > it1_c) == (it1_c < it1_c) );
                    CHECK( (it1_c > it2_c) == (it2_c < it1_c) );
                    CHECK( (it1_c > it3_c) == (it3_c < it1_c) );
                    CHECK( (it2_c > it3_c) == (it3_c < it2_c) );
                }
            }

            // comparison: greater than or equal
            {
                if (j.type() == json::value_t::object)
                {
                    CHECK_THROWS_AS(it1 >= it1, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1 >= it2, json::invalid_iterator&);
                    CHECK_THROWS_AS(it2 >= it3, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1 >= it3, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1_c >= it1_c, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1_c >= it2_c, json::invalid_iterator&);
                    CHECK_THROWS_AS(it2_c >= it3_c, json::invalid_iterator&);
                    CHECK_THROWS_AS(it1_c >= it3_c, json::invalid_iterator&);
#if JSON_DIAGNOSTICS
                    CHECK_THROWS_WITH(it1 >= it1, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 >= it2, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2 >= it3, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 >= it3, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c >= it1_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c >= it2_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2_c >= it3_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c >= it3_c, "[json.exception.invalid_iterator.213] (/5) cannot compare order of object iterators");
#else
                    CHECK_THROWS_WITH(it1 >= it1, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 >= it2, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2 >= it3, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1 >= it3, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c >= it1_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c >= it2_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it2_c >= it3_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
                    CHECK_THROWS_WITH(it1_c >= it3_c, "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
#endif
                }
                else
                {
                    // check definition
                    CHECK( (it1 >= it1) == !(it1 < it1) );
                    CHECK( (it1 >= it2) == !(it1 < it2) );
                    CHECK( (it1 >= it3) == !(it1 < it3) );
                    CHECK( (it2 >= it3) == !(it2 < it3) );
                    CHECK( (it1_c >= it1_c) == !(it1_c < it1_c) );
                    CHECK( (it1_c >= it2_c) == !(it1_c < it2_c) );
                    CHECK( (it1_c >= it3_c) == !(it1_c < it3_c) );
                    CHECK( (it2_c >= it3_c) == !(it2_c < it3_c) );
                }
            }
        }

        // check exceptions if different objects are compared
        for (auto j : j_values)
        {
            for (auto k : j_values)
            {
                if (j != k)
                {
                    CHECK_THROWS_AS(j.rbegin() == k.rbegin(), json::invalid_iterator&);
                    CHECK_THROWS_AS(j.crbegin() == k.crbegin(), json::invalid_iterator&);
                    CHECK_THROWS_AS(j.rbegin() < k.rbegin(), json::invalid_iterator&);
                    CHECK_THROWS_AS(j.crbegin() < k.crbegin(), json::invalid_iterator&);
#if JSON_DIAGNOSTICS
                    // the output differs in each loop, so we cannot fix a string for the expected exception
#else
                    CHECK_THROWS_WITH(j.rbegin() == k.rbegin(), "[json.exception.invalid_iterator.212] cannot compare iterators of different containers");
                    CHECK_THROWS_WITH(j.crbegin() == k.crbegin(), "[json.exception.invalid_iterator.212] cannot compare iterators of different containers");
                    CHECK_THROWS_WITH(j.rbegin() < k.rbegin(), "[json.exception.invalid_iterator.212] cannot compare iterators of different containers");
                    CHECK_THROWS_WITH(j.crbegin() < k.crbegin(), "[json.exception.invalid_iterator.212] cannot compare iterators of different containers");
#endif
                }
            }
        }
    }

    SECTION("reverse iterator arithmetic")
    {
        json j_object = {{"one", 1}, {"two", 2}, {"three", 3}};
        json j_array = {1, 2, 3, 4, 5, 6};
        json j_null = nullptr;
        json j_value = 42;

        SECTION("addition and subtraction")
        {
            SECTION("object")
            {
                {
                    auto it = j_object.rbegin();
                    CHECK_THROWS_AS(it += 1, json::invalid_iterator&);
                    CHECK_THROWS_WITH(it += 1, "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
                }
                {
                    auto it = j_object.crbegin();
                    CHECK_THROWS_AS(it += 1, json::invalid_iterator&);
                    CHECK_THROWS_WITH(it += 1, "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
                }
                {
                    auto it = j_object.rbegin();
                    CHECK_THROWS_AS(it + 1, json::invalid_iterator&);
                    CHECK_THROWS_WITH(it + 1, "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
                }
                {
                    auto it = j_object.crbegin();
                    CHECK_THROWS_AS(it + 1, json::invalid_iterator&);
                    CHECK_THROWS_WITH(it + 1, "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
                }
                {
                    auto it = j_object.rbegin();
                    CHECK_THROWS_AS(1 + it, json::invalid_iterator&);
                    CHECK_THROWS_WITH(1 + it, "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
                }
                {
                    auto it = j_object.crbegin();
                    CHECK_THROWS_AS(1 + it, json::invalid_iterator&);
                    CHECK_THROWS_WITH(1 + it, "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
                }
                {
                    auto it = j_object.rbegin();
                    CHECK_THROWS_AS(it -= 1, json::invalid_iterator&);
                    CHECK_THROWS_WITH(it -= 1, "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
                }
                {
                    auto it = j_object.crbegin();
                    CHECK_THROWS_AS(it -= 1, json::invalid_iterator&);
                    CHECK_THROWS_WITH(it -= 1, "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
                }
                {
                    auto it = j_object.rbegin();
                    CHECK_THROWS_AS(it - 1, json::invalid_iterator&);
                    CHECK_THROWS_WITH(it - 1, "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
                }
                {
                    auto it = j_object.crbegin();
                    CHECK_THROWS_AS(it - 1, json::invalid_iterator&);
                    CHECK_THROWS_WITH(it - 1, "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
                }
                {
                    auto it = j_object.rbegin();
                    CHECK_THROWS_AS(it - it, json::invalid_iterator&);
                    CHECK_THROWS_WITH(it - it, "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
                }
                {
                    auto it = j_object.crbegin();
                    CHECK_THROWS_AS(it - it, json::invalid_iterator&);
                    CHECK_THROWS_WITH(it - it, "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
                }
            }

            SECTION("array")
            {
                {
                    auto it = j_array.rbegin();
                    it += 3;
                    CHECK((j_array.rbegin() + 3) == it);
                    CHECK(json::reverse_iterator(3 + j_array.rbegin()) == it);
                    CHECK((it - 3) == j_array.rbegin());
                    CHECK((it - j_array.rbegin()) == 3);
                    CHECK(*it == json(3));
                    it -= 2;
                    CHECK(*it == json(5));
                }
                {
                    auto it = j_array.crbegin();
                    it += 3;
                    CHECK((j_array.crbegin() + 3) == it);
                    CHECK(json::const_reverse_iterator(3 + j_array.crbegin()) == it);
                    CHECK((it - 3) == j_array.crbegin());
                    CHECK((it - j_array.crbegin()) == 3);
                    CHECK(*it == json(3));
                    it -= 2;
                    CHECK(*it == json(5));
                }
            }

            SECTION("null")
            {
                {
                    auto it = j_null.rbegin();
                    it += 3;
                    CHECK((j_null.rbegin() + 3) == it);
                    CHECK(json::reverse_iterator(3 + j_null.rbegin()) == it);
                    CHECK((it - 3) == j_null.rbegin());
                    CHECK((it - j_null.rbegin()) == 3);
                    CHECK(it != j_null.rend());
                    it -= 3;
                    CHECK(it == j_null.rend());
                }
                {
                    auto it = j_null.crbegin();
                    it += 3;
                    CHECK((j_null.crbegin() + 3) == it);
                    CHECK(json::const_reverse_iterator(3 + j_null.crbegin()) == it);
                    CHECK((it - 3) == j_null.crbegin());
                    CHECK((it - j_null.crbegin()) == 3);
                    CHECK(it != j_null.crend());
                    it -= 3;
                    CHECK(it == j_null.crend());
                }
            }

            SECTION("value")
            {
                {
                    auto it = j_value.rbegin();
                    it += 3;
                    CHECK((j_value.rbegin() + 3) == it);
                    CHECK(json::reverse_iterator(3 + j_value.rbegin()) == it);
                    CHECK((it - 3) == j_value.rbegin());
                    CHECK((it - j_value.rbegin()) == 3);
                    CHECK(it != j_value.rend());
                    it -= 3;
                    CHECK(*it == json(42));
                }
                {
                    auto it = j_value.crbegin();
                    it += 3;
                    CHECK((j_value.crbegin() + 3) == it);
                    CHECK(json::const_reverse_iterator(3 + j_value.crbegin()) == it);
                    CHECK((it - 3) == j_value.crbegin());
                    CHECK((it - j_value.crbegin()) == 3);
                    CHECK(it != j_value.crend());
                    it -= 3;
                    CHECK(*it == json(42));
                }
            }
        }

        SECTION("subscript operator")
        {
            SECTION("object")
            {
                {
                    auto it = j_object.rbegin();
                    CHECK_THROWS_AS(it[0], json::invalid_iterator&);
                    CHECK_THROWS_AS(it[1], json::invalid_iterator&);
                    CHECK_THROWS_WITH(it[0], "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
                    CHECK_THROWS_WITH(it[1], "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
                }
                {
                    auto it = j_object.crbegin();
                    CHECK_THROWS_AS(it[0], json::invalid_iterator&);
                    CHECK_THROWS_AS(it[1], json::invalid_iterator&);
                    CHECK_THROWS_WITH(it[0], "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
                    CHECK_THROWS_WITH(it[1], "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
                }
            }

            SECTION("array")
            {
                {
                    auto it = j_array.rbegin();
                    CHECK(it[0] == json(6));
                    CHECK(it[1] == json(5));
                    CHECK(it[2] == json(4));
                    CHECK(it[3] == json(3));
                    CHECK(it[4] == json(2));
                    CHECK(it[5] == json(1));
                }
                {
                    auto it = j_array.crbegin();
                    CHECK(it[0] == json(6));
                    CHECK(it[1] == json(5));
                    CHECK(it[2] == json(4));
                    CHECK(it[3] == json(3));
                    CHECK(it[4] == json(2));
                    CHECK(it[5] == json(1));
                }
            }

            SECTION("null")
            {
                {
                    auto it = j_null.rbegin();
                    CHECK_THROWS_AS(it[0], json::invalid_iterator&);
                    CHECK_THROWS_AS(it[1], json::invalid_iterator&);
                    CHECK_THROWS_WITH(it[0], "[json.exception.invalid_iterator.214] cannot get value");
                    CHECK_THROWS_WITH(it[1], "[json.exception.invalid_iterator.214] cannot get value");
                }
                {
                    auto it = j_null.crbegin();
                    CHECK_THROWS_AS(it[0], json::invalid_iterator&);
                    CHECK_THROWS_AS(it[1], json::invalid_iterator&);
                    CHECK_THROWS_WITH(it[0], "[json.exception.invalid_iterator.214] cannot get value");
                    CHECK_THROWS_WITH(it[1], "[json.exception.invalid_iterator.214] cannot get value");
                }
            }

            SECTION("value")
            {
                {
                    auto it = j_value.rbegin();
                    CHECK(it[0] == json(42));
                    CHECK_THROWS_AS(it[1], json::invalid_iterator&);
                    CHECK_THROWS_WITH(it[1], "[json.exception.invalid_iterator.214] cannot get value");
                }
                {
                    auto it = j_value.crbegin();
                    CHECK(it[0] == json(42));
                    CHECK_THROWS_AS(it[1], json::invalid_iterator&);
                    CHECK_THROWS_WITH(it[1], "[json.exception.invalid_iterator.214] cannot get value");
                }
            }
        }
    }
}
