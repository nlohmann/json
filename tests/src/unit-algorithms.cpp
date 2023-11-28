//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.11.3
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2023 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <algorithm>
#include <nlohmann/json.hpp>
using nlohmann::json;

TEST_CASE("algorithms")
{
    json j_array = {13, 29, 3, {{"one", 1}, {"two", 2}}, true, false, {1, 2, 3}, "foo", "baz"};
    json j_object = {{"one", 1}, {"two", 2}};

    SECTION("non-modifying sequence operations")
    {
        SECTION("std::all_of")
        {
            CHECK(std::all_of(j_array.begin(), j_array.end(), [](const json & value)
            {
                return !value.empty();
            }));
            CHECK(std::all_of(j_object.begin(), j_object.end(), [](const json & value)
            {
                return value.type() == json::value_t::number_integer;
            }));
        }

        SECTION("std::any_of")
        {
            CHECK(std::any_of(j_array.begin(), j_array.end(), [](const json & value)
            {
                return value.is_string() && value.get<std::string>() == "foo";
            }));
            CHECK(std::any_of(j_object.begin(), j_object.end(), [](const json & value)
            {
                return value.get<int>() > 1;
            }));
        }

        SECTION("std::none_of")
        {
            CHECK(std::none_of(j_array.begin(), j_array.end(), [](const json & value)
            {
                return value.empty();
            }));
            CHECK(std::none_of(j_object.begin(), j_object.end(), [](const json & value)
            {
                return value.get<int>() <= 0;
            }));
        }

        SECTION("std::for_each")
        {
            SECTION("reading")
            {
                int sum = 0;

                std::for_each(j_array.cbegin(), j_array.cend(), [&sum](const json & value)
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

                std::for_each(j_array.begin(), j_array.end(), add17);

                CHECK(j_array[6] == json({1, 2, 3, 17}));
            }
        }

        SECTION("std::count")
        {
            CHECK(std::count(j_array.begin(), j_array.end(), json(true)) == 1);
        }

        SECTION("std::count_if")
        {
            CHECK(std::count_if(j_array.begin(), j_array.end(), [](const json & value)
            {
                return (value.is_number());
            }) == 3);
            CHECK(std::count_if(j_array.begin(), j_array.end(), [](const json&)
            {
                return true;
            }) == 9);
        }

        SECTION("std::mismatch")
        {
            json j_array2 = {13, 29, 3, {{"one", 1}, {"two", 2}, {"three", 3}}, true, false, {1, 2, 3}, "foo", "baz"};
            auto res = std::mismatch(j_array.begin(), j_array.end(), j_array2.begin());
            CHECK(*res.first == json({{"one", 1}, {"two", 2}}));
            CHECK(*res.second == json({{"one", 1}, {"two", 2}, {"three", 3}}));
        }

        SECTION("std::equal")
        {
            SECTION("using operator==")
            {
                CHECK(std::equal(j_array.begin(), j_array.end(), j_array.begin()));
                CHECK(std::equal(j_object.begin(), j_object.end(), j_object.begin()));
                CHECK(!std::equal(j_array.begin(), j_array.end(), j_object.begin()));
            }

            SECTION("using user-defined comparison")
            {
                // compare objects only by size of its elements
                json j_array2 = {13, 29, 3, {"Hello", "World"}, true, false, {{"one", 1}, {"two", 2}, {"three", 3}}, "foo", "baz"};
                CHECK(!std::equal(j_array.begin(), j_array.end(), j_array2.begin()));
                CHECK(std::equal(j_array.begin(), j_array.end(), j_array2.begin(),
                                 [](const json & a, const json & b)
                {
                    return (a.size() == b.size());
                }));
            }
        }

        SECTION("std::find")
        {
            auto it = std::find(j_array.begin(), j_array.end(), json(false));
            CHECK(std::distance(j_array.begin(), it) == 5);
        }

        SECTION("std::find_if")
        {
            auto it = std::find_if(j_array.begin(), j_array.end(),
                                   [](const json & value)
            {
                return value.is_boolean();
            });
            CHECK(std::distance(j_array.begin(), it) == 4);
        }

        SECTION("std::find_if_not")
        {
            auto it = std::find_if_not(j_array.begin(), j_array.end(),
                                       [](const json & value)
            {
                return value.is_number();
            });
            CHECK(std::distance(j_array.begin(), it) == 3);
        }

        SECTION("std::adjacent_find")
        {
            CHECK(std::adjacent_find(j_array.begin(), j_array.end()) == j_array.end());
            CHECK(std::adjacent_find(j_array.begin(), j_array.end(),
                                     [](const json & v1, const json & v2)
            {
                return v1.type() == v2.type();
            }) == j_array.begin());
        }
    }

    SECTION("modifying sequence operations")
    {
        SECTION("std::reverse")
        {
            std::reverse(j_array.begin(), j_array.end());
            CHECK(j_array == json({"baz", "foo", {1, 2, 3}, false, true, {{"one", 1}, {"two", 2}}, 3, 29, 13}));
        }

        SECTION("std::rotate")
        {
            std::rotate(j_array.begin(), j_array.begin() + 1, j_array.end());
            CHECK(j_array == json({29, 3, {{"one", 1}, {"two", 2}}, true, false, {1, 2, 3}, "foo", "baz", 13}));
        }

        SECTION("std::partition")
        {
            auto it = std::partition(j_array.begin(), j_array.end(), [](const json & v)
            {
                return v.is_string();
            });
            CHECK(std::distance(j_array.begin(), it) == 2);
            CHECK(!it[2].is_string());
        }
    }

    SECTION("sorting operations")
    {
        SECTION("std::sort")
        {
            SECTION("with standard comparison")
            {
                json j = {13, 29, 3, {{"one", 1}, {"two", 2}}, true, false, {1, 2, 3}, "foo", "baz", nullptr};
                std::sort(j.begin(), j.end());
                CHECK(j == json({nullptr, false, true, 3, 13, 29, {{"one", 1}, {"two", 2}}, {1, 2, 3}, "baz", "foo"}));
            }

            SECTION("with user-defined comparison")
            {
                json j = {3, {{"one", 1}, {"two", 2}}, {1, 2, 3}, nullptr};
                std::sort(j.begin(), j.end(), [](const json & a, const json & b)
                {
                    return a.size() < b.size();
                });
                CHECK(j == json({nullptr, 3, {{"one", 1}, {"two", 2}}, {1, 2, 3}}));
            }

            SECTION("sorting an object")
            {
                json j({{"one", 1}, {"two", 2}});
                CHECK_THROWS_WITH_AS(std::sort(j.begin(), j.end()), "[json.exception.invalid_iterator.209] cannot use offsets with object iterators", json::invalid_iterator&);
            }
        }

        SECTION("std::partial_sort")
        {
            json j = {13, 29, 3, {{"one", 1}, {"two", 2}}, true, false, {1, 2, 3}, "foo", "baz", nullptr};
            std::partial_sort(j.begin(), j.begin() + 4, j.end());
            CHECK(j == json({nullptr, false, true, 3, {{"one", 1}, {"two", 2}}, 29, {1, 2, 3}, "foo", "baz", 13}));
        }
    }

    SECTION("set operations")
    {
        SECTION("std::merge")
        {
            {
                json j1 = {2, 4, 6, 8};
                json j2 = {1, 2, 3, 5, 7};
                json j3;

                std::merge(j1.begin(), j1.end(), j2.begin(), j2.end(), std::back_inserter(j3));
                CHECK(j3 == json({1, 2, 2, 3, 4, 5, 6, 7, 8}));
            }
        }

        SECTION("std::set_difference")
        {
            json j1 = {1, 2, 3, 4, 5, 6, 7, 8};
            json j2 = {1, 2, 3, 5, 7};
            json j3;

            std::set_difference(j1.begin(), j1.end(), j2.begin(), j2.end(), std::back_inserter(j3));
            CHECK(j3 == json({4, 6, 8}));
        }

        SECTION("std::set_intersection")
        {
            json j1 = {1, 2, 3, 4, 5, 6, 7, 8};
            json j2 = {1, 2, 3, 5, 7};
            json j3;

            std::set_intersection(j1.begin(), j1.end(), j2.begin(), j2.end(), std::back_inserter(j3));
            CHECK(j3 == json({1, 2, 3, 5, 7}));
        }

        SECTION("std::set_union")
        {
            json j1 = {2, 4, 6, 8};
            json j2 = {1, 2, 3, 5, 7};
            json j3;

            std::set_union(j1.begin(), j1.end(), j2.begin(), j2.end(), std::back_inserter(j3));
            CHECK(j3 == json({1, 2, 3, 4, 5, 6, 7, 8}));
        }

        SECTION("std::set_symmetric_difference")
        {
            json j1 = {2, 4, 6, 8};
            json j2 = {1, 2, 3, 5, 7};
            json j3;

            std::set_symmetric_difference(j1.begin(), j1.end(), j2.begin(), j2.end(), std::back_inserter(j3));
            CHECK(j3 == json({1, 3, 4, 5, 6, 7, 8}));
        }
    }

    SECTION("heap operations")
    {
        std::make_heap(j_array.begin(), j_array.end());
        CHECK(std::is_heap(j_array.begin(), j_array.end()));
        std::sort_heap(j_array.begin(), j_array.end());
        CHECK(j_array == json({false, true, 3, 13, 29, {{"one", 1}, {"two", 2}}, {1, 2, 3}, "baz", "foo"}));
    }

    SECTION("iota")
    {
        SECTION("int")
        {
            json json_arr = {0, 5, 2, 4, 10, 20, 30, 40, 50, 1};
            std::iota(json_arr.begin(), json_arr.end(), 0);
            CHECK(json_arr == json({0, 1, 2, 3, 4, 5, 6, 7, 8, 9}));
        }
        SECTION("double")
        {
            json json_arr = {0.5, 1.5, 1.3, 4.1, 10.2, 20.5, 30.6, 40.1, 50.22, 1.5};
            std::iota(json_arr.begin(), json_arr.end(), 0.5);
            CHECK(json_arr == json({0.5, 1.5, 2.5, 3.5, 4.5, 5.5, 6.5, 7.5, 8.5, 9.5}));
        }

        SECTION("char")
        {
            json json_arr = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', '0', '1'};
            std::iota(json_arr.begin(), json_arr.end(), '0');
            CHECK(json_arr == json({'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}));
        }
    }

    SECTION("copy")
    {
        SECTION("copy without if")
        {
            json dest_arr;
            const json source_arr = {1, 2, 3, 4};

            std::copy(source_arr.begin(), source_arr.end(), std::back_inserter(dest_arr));

            CHECK(dest_arr == source_arr);
        }
        SECTION("copy if")
        {
            json dest_arr;
            const json source_arr = {0, 3, 6, 9, 12, 15, 20};

            std::copy_if(source_arr.begin(), source_arr.end(), std::back_inserter(dest_arr), [](const json & _value)
            {
                return _value.get<int>() % 3 == 0;
            });
            CHECK(dest_arr == json({0, 3, 6, 9, 12, 15}));
        }
        SECTION("copy n")
        {
            const json source_arr = {0, 1, 2, 3, 4, 5, 6, 7};
            json dest_arr;
            const unsigned char numToCopy = 2;

            std::copy_n(source_arr.begin(), numToCopy, std::back_inserter(dest_arr));
            CHECK(dest_arr == json{0, 1});

        }
        SECTION("copy n chars")
        {
            const json source_arr = {'1', '2', '3', '4', '5', '6', '7'};
            json dest_arr;
            const unsigned char numToCopy = 4;

            std::copy_n(source_arr.begin(), numToCopy, std::back_inserter(dest_arr));
            CHECK(dest_arr == json{'1', '2', '3', '4'});
        }
    }

}
