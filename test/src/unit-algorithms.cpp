/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.9.1
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
using namespace std;

TEST_CASE("algorithms")
{
    json j_array = {13, 29, 3, {{"one", 1}, {"two", 2}}, true, false, {1, 2, 3}, "foo", "baz"};
    json j_object = {{"one", 1}, {"two", 2}};

    SECTION("non-modifying sequence operations")
    {
        SECTION("all_of")
        {
            CHECK(all_of(j_array.begin(), j_array.end(), [](const json & value)
            {
                return value.size() > 0;
            }));
            CHECK(all_of(j_object.begin(), j_object.end(), [](const json & value)
            {
                return value.type() == json::value_t::number_integer;
            }));
        }

        SECTION("any_of")
        {
            CHECK(any_of(j_array.begin(), j_array.end(), [](const json & value)
            {
                return value.is_string() && value.get<string>() == "foo";
            }));
            CHECK(any_of(j_object.begin(), j_object.end(), [](const json & value)
            {
                return value.get<int>() > 1;
            }));
        }

        SECTION("none_of")
        {
            CHECK(none_of(j_array.begin(), j_array.end(), [](const json & value)
            {
                return value.size() == 0;
            }));
            CHECK(none_of(j_object.begin(), j_object.end(), [](const json & value)
            {
                return value.get<int>() <= 0;
            }));
        }

        SECTION("for_each")
        {
            SECTION("reading")
            {
                int sum = 0;

                for_each(j_array.cbegin(), j_array.cend(), [&sum](const json & value)
                {
                    if (value.is_number())
                    {
                        sum += static_cast<int>(value);
                    }
                });

                CHECK(sum == 45);
            }

            SECTION("writing")
            {
                auto add17 = [](json & value)
                {
                    if (value.is_array())
                    {
                        value.push_back(17);
                    }
                };

                for_each(j_array.begin(), j_array.end(), add17);

                CHECK(j_array[6] == json({1, 2, 3, 17}));
            }
        }

        SECTION("count")
        {
            CHECK(count(j_array.begin(), j_array.end(), json(true)) == 1);
        }

        SECTION("count_if")
        {
            CHECK(count_if(j_array.begin(), j_array.end(), [](const json & value)
            {
                return (value.is_number());
            }) == 3);
            CHECK(count_if(j_array.begin(), j_array.end(), [](const json&)
            {
                return true;
            }) == 9);
        }

        SECTION("mismatch")
        {
            json j_array2 = {13, 29, 3, {{"one", 1}, {"two", 2}, {"three", 3}}, true, false, {1, 2, 3}, "foo", "baz"};
            auto res = mismatch(j_array.begin(), j_array.end(), j_array2.begin());
            CHECK(*res.first == json({{"one", 1}, {"two", 2}}));
            CHECK(*res.second == json({{"one", 1}, {"two", 2}, {"three", 3}}));
        }

        SECTION("equal")
        {
            SECTION("using operator==")
            {
                CHECK(equal(j_array.begin(), j_array.end(), j_array.begin()));
                CHECK(equal(j_object.begin(), j_object.end(), j_object.begin()));
                CHECK(!equal(j_array.begin(), j_array.end(), j_object.begin()));
            }

            SECTION("using user-defined comparison")
            {
                // compare objects only by size of its elements
                json j_array2 = {13, 29, 3, {"Hello", "World"}, true, false, {{"one", 1}, {"two", 2}, {"three", 3}}, "foo", "baz"};
                CHECK(!equal(j_array.begin(), j_array.end(), j_array2.begin()));
                CHECK(equal(j_array.begin(), j_array.end(), j_array2.begin(),
                                 [](const json & a, const json & b)
                {
                    return (a.size() == b.size());
                }));
            }
        }

        SECTION("find")
        {
            auto it = find(j_array.begin(), j_array.end(), json(false));
            CHECK(distance(j_array.begin(), it) == 5);
        }

        SECTION("find_if")
        {
            auto it = find_if(j_array.begin(), j_array.end(),
                                   [](const json & value)
            {
                return value.is_boolean();
            });
            CHECK(distance(j_array.begin(), it) == 4);
        }

        SECTION("find_if_not")
        {
            auto it = find_if_not(j_array.begin(), j_array.end(),
                                       [](const json & value)
            {
                return value.is_number();
            });
            CHECK(distance(j_array.begin(), it) == 3);
        }

        SECTION("adjacent_find")
        {
            CHECK(adjacent_find(j_array.begin(), j_array.end()) == j_array.end());
            CHECK(adjacent_find(j_array.begin(), j_array.end(),
                                     [](const json & v1, const json & v2)
            {
                return v1.type() == v2.type();
            }) == j_array.begin());
        }
    }

    SECTION("modifying sequence operations")
    {
        SECTION("reverse")
        {
            reverse(j_array.begin(), j_array.end());
            CHECK(j_array == json({"baz", "foo", {1, 2, 3}, false, true, {{"one", 1}, {"two", 2}}, 3, 29, 13}));
        }

        SECTION("rotate")
        {
            rotate(j_array.begin(), j_array.begin() + 1, j_array.end());
            CHECK(j_array == json({29, 3, {{"one", 1}, {"two", 2}}, true, false, {1, 2, 3}, "foo", "baz", 13}));
        }

        SECTION("partition")
        {
            auto it = partition(j_array.begin(), j_array.end(), [](const json & v)
            {
                return v.is_string();
            });
            CHECK(distance(j_array.begin(), it) == 2);
            CHECK(!it[2].is_string());
        }
    }

    SECTION("sorting operations")
    {
        SECTION("sort")
        {
            SECTION("with standard comparison")
            {
                json j = {13, 29, 3, {{"one", 1}, {"two", 2}}, true, false, {1, 2, 3}, "foo", "baz", nullptr};
                sort(j.begin(), j.end());
                CHECK(j == json({nullptr, false, true, 3, 13, 29, {{"one", 1}, {"two", 2}}, {1, 2, 3}, "baz", "foo"}));
            }

            SECTION("with user-defined comparison")
            {
                json j = {3, {{"one", 1}, {"two", 2}}, {1, 2, 3}, nullptr};
                sort(j.begin(), j.end(), [](const json & a, const json & b)
                {
                    return a.size() < b.size();
                });
                CHECK(j == json({nullptr, 3, {{"one", 1}, {"two", 2}}, {1, 2, 3}}));
            }

            SECTION("sorting an object")
            {
                json j({{"one", 1}, {"two", 2}});
                CHECK_THROWS_AS(sort(j.begin(), j.end()), json::invalid_iterator&);
                CHECK_THROWS_WITH(sort(j.begin(), j.end()),
                                  "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
            }
        }

        SECTION("partial_sort")
        {
            json j = {13, 29, 3, {{"one", 1}, {"two", 2}}, true, false, {1, 2, 3}, "foo", "baz", nullptr};
            partial_sort(j.begin(), j.begin() + 4, j.end());
            CHECK(j == json({nullptr, false, true, 3, {{"one", 1}, {"two", 2}}, 29, {1, 2, 3}, "foo", "baz", 13}));
        }
    }

    SECTION("set operations")
    {
        SECTION("merge")
        {
            {
                json j1 = {2, 4, 6, 8};
                json j2 = {1, 2, 3, 5, 7};
                json j3;

                merge(j1.begin(), j1.end(), j2.begin(), j2.end(), back_inserter(j3));
                CHECK(j3 == json({1, 2, 2, 3, 4, 5, 6, 7, 8}));
            }
        }

        SECTION("set_difference")
        {
            json j1 = {1, 2, 3, 4, 5, 6, 7, 8};
            json j2 = {1, 2, 3, 5, 7};
            json j3;

            set_difference(j1.begin(), j1.end(), j2.begin(), j2.end(), back_inserter(j3));
            CHECK(j3 == json({4, 6, 8}));
        }

        SECTION("set_intersection")
        {
            json j1 = {1, 2, 3, 4, 5, 6, 7, 8};
            json j2 = {1, 2, 3, 5, 7};
            json j3;

            set_intersection(j1.begin(), j1.end(), j2.begin(), j2.end(), back_inserter(j3));
            CHECK(j3 == json({1, 2, 3, 5, 7}));
        }

        SECTION("set_union")
        {
            json j1 = {2, 4, 6, 8};
            json j2 = {1, 2, 3, 5, 7};
            json j3;

            set_union(j1.begin(), j1.end(), j2.begin(), j2.end(), back_inserter(j3));
            CHECK(j3 == json({1, 2, 3, 4, 5, 6, 7, 8}));
        }

        SECTION("set_symmetric_difference")
        {
            json j1 = {2, 4, 6, 8};
            json j2 = {1, 2, 3, 5, 7};
            json j3;

            set_symmetric_difference(j1.begin(), j1.end(), j2.begin(), j2.end(), back_inserter(j3));
            CHECK(j3 == json({1, 3, 4, 5, 6, 7, 8}));
        }
    }

    SECTION("heap operations")
    {
        make_heap(j_array.begin(), j_array.end());
        CHECK(is_heap(j_array.begin(), j_array.end()));
        sort_heap(j_array.begin(), j_array.end());
        CHECK(j_array == json({false, true, 3, 13, 29, {{"one", 1}, {"two", 2}}, {1, 2, 3}, "baz", "foo"}));
    }
}
