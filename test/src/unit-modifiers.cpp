/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 2.0.10
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
Copyright (c) 2013-2017 Niels Lohmann <http://nlohmann.me>.

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

#include "catch.hpp"

#include "json.hpp"
using nlohmann::json;

TEST_CASE("modifiers")
{
    SECTION("clear()")
    {
        SECTION("boolean")
        {
            json j = true;

            j.clear();
            CHECK(j == json(json::value_t::boolean));
        }

        SECTION("string")
        {
            json j = "hello world";

            j.clear();
            CHECK(j == json(json::value_t::string));
        }

        SECTION("array")
        {
            SECTION("empty array")
            {
                json j = json::array();

                j.clear();
                CHECK(j.empty());
                CHECK(j == json(json::value_t::array));
            }

            SECTION("filled array")
            {
                json j = {1, 2, 3};

                j.clear();
                CHECK(j.empty());
                CHECK(j == json(json::value_t::array));
            }
        }

        SECTION("object")
        {
            SECTION("empty object")
            {
                json j = json::object();

                j.clear();
                CHECK(j.empty());
                CHECK(j == json(json::value_t::object));
            }

            SECTION("filled object")
            {
                json j = {{"one", 1}, {"two", 2}, {"three", 3}};

                j.clear();
                CHECK(j.empty());
                CHECK(j == json(json::value_t::object));
            }
        }

        SECTION("number (integer)")
        {
            json j = 23;

            j.clear();
            CHECK(j == json(json::value_t::number_integer));
        }

        SECTION("number (unsigned)")
        {
            json j = 23u;

            j.clear();
            CHECK(j == json(json::value_t::number_integer));
        }

        SECTION("number (float)")
        {
            json j = 23.42;

            j.clear();
            CHECK(j == json(json::value_t::number_float));
        }

        SECTION("null")
        {
            json j = nullptr;

            j.clear();
            CHECK(j == json(json::value_t::null));
        }
    }

    SECTION("push_back()")
    {
        SECTION("to array")
        {
            SECTION("json&&")
            {
                SECTION("null")
                {
                    json j;
                    j.push_back(1);
                    j.push_back(2);
                    CHECK(j.type() == json::value_t::array);
                    CHECK(j == json({1, 2}));
                }

                SECTION("array")
                {
                    json j = {1, 2, 3};
                    j.push_back("Hello");
                    CHECK(j.type() == json::value_t::array);
                    CHECK(j == json({1, 2, 3, "Hello"}));
                }

                SECTION("other type")
                {
                    json j = 1;
                    CHECK_THROWS_AS(j.push_back("Hello"), std::domain_error);
                    CHECK_THROWS_WITH(j.push_back("Hello"), "cannot use push_back() with number");
                }
            }

            SECTION("const json&")
            {
                SECTION("null")
                {
                    json j;
                    json k(1);
                    j.push_back(k);
                    j.push_back(k);
                    CHECK(j.type() == json::value_t::array);
                    CHECK(j == json({1, 1}));
                }

                SECTION("array")
                {
                    json j = {1, 2, 3};
                    json k("Hello");
                    j.push_back(k);
                    CHECK(j.type() == json::value_t::array);
                    CHECK(j == json({1, 2, 3, "Hello"}));
                }

                SECTION("other type")
                {
                    json j = 1;
                    json k("Hello");
                    CHECK_THROWS_AS(j.push_back(k), std::domain_error);
                    CHECK_THROWS_WITH(j.push_back(k), "cannot use push_back() with number");
                }
            }
        }

        SECTION("to object")
        {
            SECTION("null")
            {
                json j;
                j.push_back(json::object_t::value_type({"one", 1}));
                j.push_back(json::object_t::value_type({"two", 2}));
                CHECK(j.type() == json::value_t::object);
                CHECK(j.size() == 2);
                CHECK(j["one"] == json(1));
                CHECK(j["two"] == json(2));
            }

            SECTION("object")
            {
                json j(json::value_t::object);
                j.push_back(json::object_t::value_type({"one", 1}));
                j.push_back(json::object_t::value_type({"two", 2}));
                CHECK(j.size() == 2);
                CHECK(j["one"] == json(1));
                CHECK(j["two"] == json(2));
            }

            SECTION("other type")
            {
                json j = 1;
                json k("Hello");
                CHECK_THROWS_AS(j.push_back(json::object_t::value_type({"one", 1})), std::domain_error);
                CHECK_THROWS_WITH(j.push_back(json::object_t::value_type({"one", 1})),
                                  "cannot use push_back() with number");
            }
        }

        SECTION("with initializer_list")
        {
            SECTION("null")
            {
                json j;
                j.push_back({"foo", "bar"});
                CHECK(j == json::array({{"foo", "bar"}}));

                json k;
                k.push_back({1, 2, 3});
                CHECK(k == json::array({{1, 2, 3}}));
            }

            SECTION("array")
            {
                json j = {1, 2, 3};
                j.push_back({"foo", "bar"});
                CHECK(j == json({1, 2, 3, {"foo", "bar"}}));

                json k = {1, 2, 3};
                k.push_back({1, 2, 3});
                CHECK(k == json({1, 2, 3, {1, 2, 3}}));
            }

            SECTION("object")
            {
                json j = {{"key1", 1}};
                j.push_back({"key2", "bar"});
                CHECK(j == json({{"key1", 1}, {"key2", "bar"}}));

                json k = {{"key1", 1}};
                CHECK_THROWS_AS(k.push_back({1, 2, 3, 4}), std::domain_error);
                CHECK_THROWS_WITH(k.push_back({1, 2, 3, 4}), "cannot use push_back() with object");
            }
        }
    }

    SECTION("emplace_back()")
    {
        SECTION("to array")
        {
            SECTION("null")
            {
                json j;
                j.emplace_back(1);
                j.emplace_back(2);
                CHECK(j.type() == json::value_t::array);
                CHECK(j == json({1, 2}));
            }

            SECTION("array")
            {
                json j = {1, 2, 3};
                j.emplace_back("Hello");
                CHECK(j.type() == json::value_t::array);
                CHECK(j == json({1, 2, 3, "Hello"}));
            }

            SECTION("multiple values")
            {
                json j;
                j.emplace_back(3, "foo");
                CHECK(j.type() == json::value_t::array);
                CHECK(j == json({{"foo", "foo", "foo"}}));
            }
        }

        SECTION("other type")
        {
            json j = 1;
            CHECK_THROWS_AS(j.emplace_back("Hello"), std::domain_error);
            CHECK_THROWS_WITH(j.emplace_back("Hello"), "cannot use emplace_back() with number");
        }
    }

    SECTION("emplace()")
    {
        SECTION("to object")
        {
            SECTION("null")
            {
                // start with a null value
                json j;

                // add a new key
                auto res1 = j.emplace("foo", "bar");
                CHECK(res1.second == true);
                CHECK(*res1.first == "bar");

                // the null value is changed to an object
                CHECK(j.type() == json::value_t::object);

                // add a new key
                auto res2 = j.emplace("baz", "bam");
                CHECK(res2.second == true);
                CHECK(*res2.first == "bam");

                // we try to insert at given key - no change
                auto res3 = j.emplace("baz", "bad");
                CHECK(res3.second == false);
                CHECK(*res3.first == "bam");

                // the final object
                CHECK(j == json({{"baz", "bam"}, {"foo", "bar"}}));
            }

            SECTION("object")
            {
                // start with an object
                json j = {{"foo", "bar"}};

                // add a new key
                auto res1 = j.emplace("baz", "bam");
                CHECK(res1.second == true);
                CHECK(*res1.first == "bam");

                // add an existing key
                auto res2 = j.emplace("foo", "bad");
                CHECK(res2.second == false);
                CHECK(*res2.first == "bar");

                // check final object
                CHECK(j == json({{"baz", "bam"}, {"foo", "bar"}}));
            }
        }

        SECTION("other type")
        {
            json j = 1;
            CHECK_THROWS_AS(j.emplace("foo", "bar"), std::domain_error);
            CHECK_THROWS_WITH(j.emplace("foo", "bar"), "cannot use emplace() with number");
        }
    }

    SECTION("operator+=")
    {
        SECTION("to array")
        {
            SECTION("json&&")
            {
                SECTION("null")
                {
                    json j;
                    j += 1;
                    j += 2;
                    CHECK(j.type() == json::value_t::array);
                    CHECK(j == json({1, 2}));
                }

                SECTION("array")
                {
                    json j = {1, 2, 3};
                    j += "Hello";
                    CHECK(j.type() == json::value_t::array);
                    CHECK(j == json({1, 2, 3, "Hello"}));
                }

                SECTION("other type")
                {
                    json j = 1;
                    CHECK_THROWS_AS(j += "Hello", std::domain_error);
                    CHECK_THROWS_WITH(j += "Hello", "cannot use push_back() with number");
                }
            }

            SECTION("const json&")
            {
                SECTION("null")
                {
                    json j;
                    json k(1);
                    j += k;
                    j += k;
                    CHECK(j.type() == json::value_t::array);
                    CHECK(j == json({1, 1}));
                }

                SECTION("array")
                {
                    json j = {1, 2, 3};
                    json k("Hello");
                    j += k;
                    CHECK(j.type() == json::value_t::array);
                    CHECK(j == json({1, 2, 3, "Hello"}));
                }

                SECTION("other type")
                {
                    json j = 1;
                    json k("Hello");
                    CHECK_THROWS_AS(j += k, std::domain_error);
                    CHECK_THROWS_WITH(j += k, "cannot use push_back() with number");
                }
            }
        }

        SECTION("to object")
        {
            SECTION("null")
            {
                json j;
                j += json::object_t::value_type({"one", 1});
                j += json::object_t::value_type({"two", 2});
                CHECK(j.type() == json::value_t::object);
                CHECK(j.size() == 2);
                CHECK(j["one"] == json(1));
                CHECK(j["two"] == json(2));
            }

            SECTION("object")
            {
                json j(json::value_t::object);
                j += json::object_t::value_type({"one", 1});
                j += json::object_t::value_type({"two", 2});
                CHECK(j.size() == 2);
                CHECK(j["one"] == json(1));
                CHECK(j["two"] == json(2));
            }

            SECTION("other type")
            {
                json j = 1;
                json k("Hello");
                CHECK_THROWS_AS(j += json::object_t::value_type({"one", 1}), std::domain_error);
                CHECK_THROWS_WITH(j += json::object_t::value_type({"one", 1}),
                                  "cannot use push_back() with number");
            }
        }

        SECTION("with initializer_list")
        {
            SECTION("null")
            {
                json j;
                j += {"foo", "bar"};
                CHECK(j == json::array({{"foo", "bar"}}));

                json k;
                k += {1, 2, 3};
                CHECK(k == json::array({{1, 2, 3}}));
            }

            SECTION("array")
            {
                json j = {1, 2, 3};
                j += {"foo", "bar"};
                CHECK(j == json({1, 2, 3, {"foo", "bar"}}));

                json k = {1, 2, 3};
                k += {1, 2, 3};
                CHECK(k == json({1, 2, 3, {1, 2, 3}}));
            }

            SECTION("object")
            {
                json j = {{"key1", 1}};
                j += {"key2", "bar"};
                CHECK(j == json({{"key1", 1}, {"key2", "bar"}}));

                json k = {{"key1", 1}};
                CHECK_THROWS_AS((k += {1, 2, 3, 4}), std::domain_error);
                CHECK_THROWS_WITH((k += {1, 2, 3, 4}), "cannot use push_back() with object");
            }
        }
    }

    SECTION("insert")
    {
        json j_array = {1, 2, 3, 4};
        json j_value = 5;

        SECTION("value at position")
        {
            SECTION("insert before begin()")
            {
                auto it = j_array.insert(j_array.begin(), j_value);
                CHECK(j_array.size() == 5);
                CHECK(*it == j_value);
                CHECK(j_array.begin() == it);
                CHECK(j_array == json({5, 1, 2, 3, 4}));
            }

            SECTION("insert in the middle")
            {
                auto it = j_array.insert(j_array.begin() + 2, j_value);
                CHECK(j_array.size() == 5);
                CHECK(*it == j_value);
                CHECK((it - j_array.begin()) == 2);
                CHECK(j_array == json({1, 2, 5, 3, 4}));
            }

            SECTION("insert before end()")
            {
                auto it = j_array.insert(j_array.end(), j_value);
                CHECK(j_array.size() == 5);
                CHECK(*it == j_value);
                CHECK((j_array.end() - it) == 1);
                CHECK(j_array == json({1, 2, 3, 4, 5}));
            }
        }

        SECTION("rvalue at position")
        {
            SECTION("insert before begin()")
            {
                auto it = j_array.insert(j_array.begin(), 5);
                CHECK(j_array.size() == 5);
                CHECK(*it == j_value);
                CHECK(j_array.begin() == it);
                CHECK(j_array == json({5, 1, 2, 3, 4}));
            }

            SECTION("insert in the middle")
            {
                auto it = j_array.insert(j_array.begin() + 2, 5);
                CHECK(j_array.size() == 5);
                CHECK(*it == j_value);
                CHECK((it - j_array.begin()) == 2);
                CHECK(j_array == json({1, 2, 5, 3, 4}));
            }

            SECTION("insert before end()")
            {
                auto it = j_array.insert(j_array.end(), 5);
                CHECK(j_array.size() == 5);
                CHECK(*it == j_value);
                CHECK((j_array.end() - it) == 1);
                CHECK(j_array == json({1, 2, 3, 4, 5}));
            }
        }

        SECTION("copies at position")
        {
            SECTION("insert before begin()")
            {
                auto it = j_array.insert(j_array.begin(), 3, 5);
                CHECK(j_array.size() == 7);
                CHECK(*it == j_value);
                CHECK(j_array.begin() == it);
                CHECK(j_array == json({5, 5, 5, 1, 2, 3, 4}));
            }

            SECTION("insert in the middle")
            {
                auto it = j_array.insert(j_array.begin() + 2, 3, 5);
                CHECK(j_array.size() == 7);
                CHECK(*it == j_value);
                CHECK((it - j_array.begin()) == 2);
                CHECK(j_array == json({1, 2, 5, 5, 5, 3, 4}));
            }

            SECTION("insert before end()")
            {
                auto it = j_array.insert(j_array.end(), 3, 5);
                CHECK(j_array.size() == 7);
                CHECK(*it == j_value);
                CHECK((j_array.end() - it) == 3);
                CHECK(j_array == json({1, 2, 3, 4, 5, 5, 5}));
            }

            SECTION("insert nothing (count = 0)")
            {
                auto pos = j_array.end();
                auto it = j_array.insert(j_array.end(), 0, 5);
                CHECK(j_array.size() == 4);
                CHECK(it == pos);
                CHECK(j_array == json({1, 2, 3, 4}));
            }
        }

        SECTION("range")
        {
            json j_other_array = {"first", "second"};

            SECTION("proper usage")
            {
                auto it = j_array.insert(j_array.end(), j_other_array.begin(), j_other_array.end());
                CHECK(j_array.size() == 6);
                CHECK(*it == *j_other_array.begin());
                CHECK((j_array.end() - it) == 2);
                CHECK(j_array == json({1, 2, 3, 4, "first", "second"}));
            }

            SECTION("empty range")
            {
                auto it = j_array.insert(j_array.end(), j_other_array.begin(), j_other_array.begin());
                CHECK(j_array.size() == 4);
                CHECK(it == j_array.end());
                CHECK(j_array == json({1, 2, 3, 4}));
            }

            SECTION("invalid iterators")
            {
                json j_other_array2 = {"first", "second"};

                CHECK_THROWS_AS(j_array.insert(j_array.end(), j_array.begin(), j_array.end()), std::domain_error);
                CHECK_THROWS_AS(j_array.insert(j_array.end(), j_other_array.begin(), j_other_array2.end()),
                                std::domain_error);

                CHECK_THROWS_WITH(j_array.insert(j_array.end(), j_array.begin(), j_array.end()),
                                  "passed iterators may not belong to container");
                CHECK_THROWS_WITH(j_array.insert(j_array.end(), j_other_array.begin(), j_other_array2.end()),
                                  "iterators do not fit");
            }
        }

        SECTION("initializer list at position")
        {
            SECTION("insert before begin()")
            {
                auto it = j_array.insert(j_array.begin(), {7, 8, 9});
                CHECK(j_array.size() == 7);
                CHECK(*it == json(7));
                CHECK(j_array.begin() == it);
                CHECK(j_array == json({7, 8, 9, 1, 2, 3, 4}));
            }

            SECTION("insert in the middle")
            {
                auto it = j_array.insert(j_array.begin() + 2, {7, 8, 9});
                CHECK(j_array.size() == 7);
                CHECK(*it == json(7));
                CHECK((it - j_array.begin()) == 2);
                CHECK(j_array == json({1, 2, 7, 8, 9, 3, 4}));
            }

            SECTION("insert before end()")
            {
                auto it = j_array.insert(j_array.end(), {7, 8, 9});
                CHECK(j_array.size() == 7);
                CHECK(*it == json(7));
                CHECK((j_array.end() - it) == 3);
                CHECK(j_array == json({1, 2, 3, 4, 7, 8, 9}));
            }
        }

        SECTION("invalid iterator")
        {
            // pass iterator to a different array
            json j_another_array = {1, 2};
            json j_yet_another_array = {"first", "second"};
            CHECK_THROWS_AS(j_array.insert(j_another_array.end(), 10), std::domain_error);
            CHECK_THROWS_AS(j_array.insert(j_another_array.end(), j_value), std::domain_error);
            CHECK_THROWS_AS(j_array.insert(j_another_array.end(), 10, 11), std::domain_error);
            CHECK_THROWS_AS(j_array.insert(j_another_array.end(), j_yet_another_array.begin(),
                                           j_yet_another_array.end()), std::domain_error);
            CHECK_THROWS_AS(j_array.insert(j_another_array.end(), {1, 2, 3, 4}), std::domain_error);

            CHECK_THROWS_WITH(j_array.insert(j_another_array.end(), 10), "iterator does not fit current value");
            CHECK_THROWS_WITH(j_array.insert(j_another_array.end(), j_value),
                              "iterator does not fit current value");
            CHECK_THROWS_WITH(j_array.insert(j_another_array.end(), 10, 11),
                              "iterator does not fit current value");
            CHECK_THROWS_WITH(j_array.insert(j_another_array.end(), j_yet_another_array.begin(),
                                             j_yet_another_array.end()), "iterator does not fit current value");
            CHECK_THROWS_WITH(j_array.insert(j_another_array.end(), {1, 2, 3, 4}),
                              "iterator does not fit current value");
        }

        SECTION("non-array type")
        {
            // call insert on a non-array type
            json j_nonarray = 3;
            json j_yet_another_array = {"first", "second"};
            CHECK_THROWS_AS(j_nonarray.insert(j_nonarray.end(), 10), std::domain_error);
            CHECK_THROWS_AS(j_nonarray.insert(j_nonarray.end(), j_value), std::domain_error);
            CHECK_THROWS_AS(j_nonarray.insert(j_nonarray.end(), 10, 11), std::domain_error);
            CHECK_THROWS_AS(j_nonarray.insert(j_nonarray.end(), j_yet_another_array.begin(),
                                              j_yet_another_array.end()), std::domain_error);
            CHECK_THROWS_AS(j_nonarray.insert(j_nonarray.end(), {1, 2, 3, 4}), std::domain_error);

            CHECK_THROWS_WITH(j_nonarray.insert(j_nonarray.end(), 10), "cannot use insert() with number");
            CHECK_THROWS_WITH(j_nonarray.insert(j_nonarray.end(), j_value), "cannot use insert() with number");
            CHECK_THROWS_WITH(j_nonarray.insert(j_nonarray.end(), 10, 11), "cannot use insert() with number");
            CHECK_THROWS_WITH(j_nonarray.insert(j_nonarray.end(), j_yet_another_array.begin(),
                                                j_yet_another_array.end()), "cannot use insert() with number");
            CHECK_THROWS_WITH(j_nonarray.insert(j_nonarray.end(), {1, 2, 3, 4}),
                              "cannot use insert() with number");
        }
    }

    SECTION("swap()")
    {
        SECTION("json")
        {
            SECTION("member swap")
            {
                json j("hello world");
                json k(42.23);

                j.swap(k);

                CHECK(j == json(42.23));
                CHECK(k == json("hello world"));
            }

            SECTION("nonmember swap")
            {
                json j("hello world");
                json k(42.23);

                std::swap(j, k);

                CHECK(j == json(42.23));
                CHECK(k == json("hello world"));
            }
        }

        SECTION("array_t")
        {
            SECTION("array_t type")
            {
                json j = {1, 2, 3, 4};
                json::array_t a = {"foo", "bar", "baz"};

                j.swap(a);

                CHECK(j == json({"foo", "bar", "baz"}));

                j.swap(a);

                CHECK(j == json({1, 2, 3, 4}));
            }

            SECTION("non-array_t type")
            {
                json j = 17;
                json::array_t a = {"foo", "bar", "baz"};

                CHECK_THROWS_AS(j.swap(a), std::domain_error);
                CHECK_THROWS_WITH(j.swap(a), "cannot use swap() with number");
            }
        }

        SECTION("object_t")
        {
            SECTION("object_t type")
            {
                json j = {{"one", 1}, {"two", 2}};
                json::object_t o = {{"cow", "Kuh"}, {"chicken", "Huhn"}};

                j.swap(o);

                CHECK(j == json({{"cow", "Kuh"}, {"chicken", "Huhn"}}));

                j.swap(o);

                CHECK(j == json({{"one", 1}, {"two", 2}}));
            }

            SECTION("non-object_t type")
            {
                json j = 17;
                json::object_t o = {{"cow", "Kuh"}, {"chicken", "Huhn"}};

                CHECK_THROWS_AS(j.swap(o), std::domain_error);
                CHECK_THROWS_WITH(j.swap(o), "cannot use swap() with number");
            }
        }

        SECTION("string_t")
        {
            SECTION("string_t type")
            {
                json j = "Hello world";
                json::string_t s = "Hallo Welt";

                j.swap(s);

                CHECK(j == json("Hallo Welt"));

                j.swap(s);

                CHECK(j == json("Hello world"));
            }

            SECTION("non-string_t type")
            {
                json j = 17;
                json::string_t s = "Hallo Welt";

                CHECK_THROWS_AS(j.swap(s), std::domain_error);
                CHECK_THROWS_WITH(j.swap(s), "cannot use swap() with number");
            }
        }
    }
}
