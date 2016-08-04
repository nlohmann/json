/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 2.0.2
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
Copyright (c) 2013-2016 Niels Lohmann <http://nlohmann.me>.

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

TEST_CASE("element access")
{
    SECTION("array")
    {
        json j = {1, 1u, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
        const json j_const = j;

        SECTION("access specified element with bounds checking")
        {
            SECTION("access within bounds")
            {
                CHECK(j.at(0) == json(1));
                CHECK(j.at(1) == json(1u));
                CHECK(j.at(2) == json(true));
                CHECK(j.at(3) == json(nullptr));
                CHECK(j.at(4) == json("string"));
                CHECK(j.at(5) == json(42.23));
                CHECK(j.at(6) == json(json::object()));
                CHECK(j.at(7) == json({1, 2, 3}));

                CHECK(j_const.at(0) == json(1));
                CHECK(j_const.at(1) == json(1u));
                CHECK(j_const.at(2) == json(true));
                CHECK(j_const.at(3) == json(nullptr));
                CHECK(j_const.at(4) == json("string"));
                CHECK(j_const.at(5) == json(42.23));
                CHECK(j_const.at(6) == json(json::object()));
                CHECK(j_const.at(7) == json({1, 2, 3}));
            }

            SECTION("access outside bounds")
            {
                CHECK_THROWS_AS(j.at(8), std::out_of_range);
                CHECK_THROWS_AS(j_const.at(8), std::out_of_range);

                CHECK_THROWS_WITH(j.at(8), "array index 8 is out of range");
                CHECK_THROWS_WITH(j_const.at(8), "array index 8 is out of range");
            }

            SECTION("access on non-array type")
            {
                SECTION("null")
                {
                    json j_nonarray(json::value_t::null);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray.at(0), std::domain_error);
                    CHECK_THROWS_AS(j_nonarray_const.at(0), std::domain_error);

                    CHECK_THROWS_WITH(j_nonarray.at(0), "cannot use at() with null");
                    CHECK_THROWS_WITH(j_nonarray_const.at(0), "cannot use at() with null");
                }

                SECTION("boolean")
                {
                    json j_nonarray(json::value_t::boolean);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray.at(0), std::domain_error);
                    CHECK_THROWS_AS(j_nonarray_const.at(0), std::domain_error);

                    CHECK_THROWS_WITH(j_nonarray.at(0), "cannot use at() with boolean");
                    CHECK_THROWS_WITH(j_nonarray_const.at(0), "cannot use at() with boolean");
                }

                SECTION("string")
                {
                    json j_nonarray(json::value_t::string);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray.at(0), std::domain_error);
                    CHECK_THROWS_AS(j_nonarray_const.at(0), std::domain_error);

                    CHECK_THROWS_WITH(j_nonarray.at(0), "cannot use at() with string");
                    CHECK_THROWS_WITH(j_nonarray_const.at(0), "cannot use at() with string");
                }

                SECTION("object")
                {
                    json j_nonarray(json::value_t::object);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray.at(0), std::domain_error);
                    CHECK_THROWS_AS(j_nonarray_const.at(0), std::domain_error);

                    CHECK_THROWS_WITH(j_nonarray.at(0), "cannot use at() with object");
                    CHECK_THROWS_WITH(j_nonarray_const.at(0), "cannot use at() with object");
                }

                SECTION("number (integer)")
                {
                    json j_nonarray(json::value_t::number_integer);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray.at(0), std::domain_error);
                    CHECK_THROWS_AS(j_nonarray_const.at(0), std::domain_error);

                    CHECK_THROWS_WITH(j_nonarray.at(0), "cannot use at() with number");
                    CHECK_THROWS_WITH(j_nonarray_const.at(0), "cannot use at() with number");
                }

                SECTION("number (unsigned)")
                {
                    json j_nonarray(json::value_t::number_unsigned);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray.at(0), std::domain_error);
                    CHECK_THROWS_AS(j_nonarray_const.at(0), std::domain_error);

                    CHECK_THROWS_WITH(j_nonarray.at(0), "cannot use at() with number");
                    CHECK_THROWS_WITH(j_nonarray_const.at(0), "cannot use at() with number");
                }

                SECTION("number (floating-point)")
                {
                    json j_nonarray(json::value_t::number_float);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray.at(0), std::domain_error);
                    CHECK_THROWS_AS(j_nonarray_const.at(0), std::domain_error);

                    CHECK_THROWS_WITH(j_nonarray.at(0), "cannot use at() with number");
                    CHECK_THROWS_WITH(j_nonarray_const.at(0), "cannot use at() with number");
                }
            }
        }

        SECTION("front and back")
        {
            CHECK(j.front() == json(1));
            CHECK(j_const.front() == json(1));
            CHECK(j.back() == json({1, 2, 3}));
            CHECK(j_const.back() == json({1, 2, 3}));
        }

        SECTION("access specified element")
        {
            SECTION("access within bounds")
            {
                CHECK(j[0] == json(1));
                CHECK(j[1] == json(1u));
                CHECK(j[2] == json(true));
                CHECK(j[3] == json(nullptr));
                CHECK(j[4] == json("string"));
                CHECK(j[5] == json(42.23));
                CHECK(j[6] == json(json::object()));
                CHECK(j[7] == json({1, 2, 3}));

                CHECK(j_const[0] == json(1));
                CHECK(j_const[1] == json(1u));
                CHECK(j_const[2] == json(true));
                CHECK(j_const[3] == json(nullptr));
                CHECK(j_const[4] == json("string"));
                CHECK(j_const[5] == json(42.23));
                CHECK(j_const[6] == json(json::object()));
                CHECK(j_const[7] == json({1, 2, 3}));
            }

            SECTION("access on non-array type")
            {
                SECTION("null")
                {
                    SECTION("standard tests")
                    {
                        json j_nonarray(json::value_t::null);
                        const json j_nonarray_const(j_nonarray);
                        CHECK_NOTHROW(j_nonarray[0]);
                        CHECK_THROWS_AS(j_nonarray_const[0], std::domain_error);
                        CHECK_THROWS_WITH(j_nonarray_const[0], "cannot use operator[] with null");
                    }

                    SECTION("implicit transformation to properly filled array")
                    {
                        json j_nonarray;
                        j_nonarray[3] = 42;
                        CHECK(j_nonarray == json({nullptr, nullptr, nullptr, 42}));
                    }
                }

                SECTION("boolean")
                {
                    json j_nonarray(json::value_t::boolean);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray[0], std::domain_error);
                    CHECK_THROWS_AS(j_nonarray_const[0], std::domain_error);
                    CHECK_THROWS_WITH(j_nonarray[0], "cannot use operator[] with boolean");
                    CHECK_THROWS_WITH(j_nonarray_const[0], "cannot use operator[] with boolean");
                }

                SECTION("string")
                {
                    json j_nonarray(json::value_t::string);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray[0], std::domain_error);
                    CHECK_THROWS_AS(j_nonarray_const[0], std::domain_error);
                    CHECK_THROWS_WITH(j_nonarray[0], "cannot use operator[] with string");
                    CHECK_THROWS_WITH(j_nonarray_const[0], "cannot use operator[] with string");
                }

                SECTION("object")
                {
                    json j_nonarray(json::value_t::object);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray[0], std::domain_error);
                    CHECK_THROWS_AS(j_nonarray_const[0], std::domain_error);
                    CHECK_THROWS_WITH(j_nonarray[0], "cannot use operator[] with object");
                    CHECK_THROWS_WITH(j_nonarray_const[0], "cannot use operator[] with object");
                }

                SECTION("number (integer)")
                {
                    json j_nonarray(json::value_t::number_integer);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray[0], std::domain_error);
                    CHECK_THROWS_AS(j_nonarray_const[0], std::domain_error);
                    CHECK_THROWS_WITH(j_nonarray[0], "cannot use operator[] with number");
                    CHECK_THROWS_WITH(j_nonarray_const[0], "cannot use operator[] with number");
                }

                SECTION("number (unsigned)")
                {
                    json j_nonarray(json::value_t::number_unsigned);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray[0], std::domain_error);
                    CHECK_THROWS_AS(j_nonarray_const[0], std::domain_error);
                    CHECK_THROWS_WITH(j_nonarray[0], "cannot use operator[] with number");
                    CHECK_THROWS_WITH(j_nonarray_const[0], "cannot use operator[] with number");
                }

                SECTION("number (floating-point)")
                {
                    json j_nonarray(json::value_t::number_float);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray[0], std::domain_error);
                    CHECK_THROWS_AS(j_nonarray_const[0], std::domain_error);
                    CHECK_THROWS_WITH(j_nonarray[0], "cannot use operator[] with number");
                    CHECK_THROWS_WITH(j_nonarray_const[0], "cannot use operator[] with number");
                }
            }
        }

        SECTION("remove specified element")
        {
            SECTION("remove element by index")
            {
                {
                    json jarray = {1, 1u, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                    jarray.erase(0);
                    CHECK(jarray == json({1u, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}}));
                }
                {
                    json jarray = {1, 1u, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                    jarray.erase(1);
                    CHECK(jarray == json({1, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}}));
                }
                {
                    json jarray = {1, 1u, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                    jarray.erase(2);
                    CHECK(jarray == json({1, 1u, nullptr, "string", 42.23, json::object(), {1, 2, 3}}));
                }
                {
                    json jarray = {1, 1u, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                    jarray.erase(3);
                    CHECK(jarray == json({1, 1u, true, "string", 42.23, json::object(), {1, 2, 3}}));
                }
                {
                    json jarray = {1, 1u, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                    jarray.erase(4);
                    CHECK(jarray == json({1, 1u, true, nullptr, 42.23, json::object(), {1, 2, 3}}));
                }
                {
                    json jarray = {1, 1u, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                    jarray.erase(5);
                    CHECK(jarray == json({1, 1u, true, nullptr, "string", json::object(), {1, 2, 3}}));
                }
                {
                    json jarray = {1, 1u, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                    jarray.erase(6);
                    CHECK(jarray == json({1, 1u, true, nullptr, "string", 42.23, {1, 2, 3}}));
                }
                {
                    json jarray = {1, 1u, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                    jarray.erase(7);
                    CHECK(jarray == json({1, 1u, true, nullptr, "string", 42.23, json::object()}));
                }
                {
                    json jarray = {1, 1u, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                    CHECK_THROWS_AS(jarray.erase(8), std::out_of_range);
                    CHECK_THROWS_WITH(jarray.erase(8), "array index 8 is out of range");
                }
            }

            SECTION("remove element by iterator")
            {
                SECTION("erase(begin())")
                {
                    {
                        json jarray = {1, 1u, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                        json::iterator it2 = jarray.erase(jarray.begin());
                        CHECK(jarray == json({1u, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}}));
                        CHECK(*it2 == json(1u));
                    }
                    {
                        json jarray = {1, 1u, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                        json::const_iterator it2 = jarray.erase(jarray.cbegin());
                        CHECK(jarray == json({1u, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}}));
                        CHECK(*it2 == json(1u));
                    }
                }

                SECTION("erase(begin(), end())")
                {
                    {
                        json jarray = {1, 1u, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                        json::iterator it2 = jarray.erase(jarray.begin(), jarray.end());
                        CHECK(jarray == json::array());
                        CHECK(it2 == jarray.end());
                    }
                    {
                        json jarray = {1, 1u, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                        json::const_iterator it2 = jarray.erase(jarray.cbegin(), jarray.cend());
                        CHECK(jarray == json::array());
                        CHECK(it2 == jarray.cend());
                    }
                }

                SECTION("erase(begin(), begin())")
                {
                    {
                        json jarray = {1, 1u, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                        json::iterator it2 = jarray.erase(jarray.begin(), jarray.begin());
                        CHECK(jarray == json({1, 1u, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}}));
                        CHECK(*it2 == json(1));
                    }
                    {
                        json jarray = {1, 1u, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                        json::const_iterator it2 = jarray.erase(jarray.cbegin(), jarray.cbegin());
                        CHECK(jarray == json({1, 1u, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}}));
                        CHECK(*it2 == json(1));
                    }
                }

                SECTION("erase at offset")
                {
                    {
                        json jarray = {1, 1u, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                        json::iterator it = jarray.begin() + 4;
                        json::iterator it2 = jarray.erase(it);
                        CHECK(jarray == json({1, 1u, true, nullptr, 42.23, json::object(), {1, 2, 3}}));
                        CHECK(*it2 == json(42.23));
                    }
                    {
                        json jarray = {1, 1u, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                        json::const_iterator it = jarray.cbegin() + 4;
                        json::const_iterator it2 = jarray.erase(it);
                        CHECK(jarray == json({1, 1u, true, nullptr, 42.23, json::object(), {1, 2, 3}}));
                        CHECK(*it2 == json(42.23));
                    }
                }

                SECTION("erase subrange")
                {
                    {
                        json jarray = {1, 1u, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                        json::iterator it2 = jarray.erase(jarray.begin() + 3, jarray.begin() + 6);
                        CHECK(jarray == json({1, 1u, true, json::object(), {1, 2, 3}}));
                        CHECK(*it2 == json::object());
                    }
                    {
                        json jarray = {1, 1u, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                        json::const_iterator it2 = jarray.erase(jarray.cbegin() + 3, jarray.cbegin() + 6);
                        CHECK(jarray == json({1, 1u, true, json::object(), {1, 2, 3}}));
                        CHECK(*it2 == json::object());
                    }
                }

                SECTION("different arrays")
                {
                    {
                        json jarray = {1, 1u, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                        json jarray2 = {"foo", "bar"};
                        CHECK_THROWS_AS(jarray.erase(jarray2.begin()), std::domain_error);
                        CHECK_THROWS_AS(jarray.erase(jarray.begin(), jarray2.end()), std::domain_error);
                        CHECK_THROWS_AS(jarray.erase(jarray2.begin(), jarray.end()), std::domain_error);
                        CHECK_THROWS_AS(jarray.erase(jarray2.begin(), jarray2.end()), std::domain_error);

                        CHECK_THROWS_WITH(jarray.erase(jarray2.begin()), "iterator does not fit current value");
                        CHECK_THROWS_WITH(jarray.erase(jarray.begin(), jarray2.end()),
                                          "iterators do not fit current value");
                        CHECK_THROWS_WITH(jarray.erase(jarray2.begin(), jarray.end()),
                                          "iterators do not fit current value");
                        CHECK_THROWS_WITH(jarray.erase(jarray2.begin(), jarray2.end()),
                                          "iterators do not fit current value");
                    }
                    {
                        json jarray = {1, 1u, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
                        json jarray2 = {"foo", "bar"};
                        CHECK_THROWS_AS(jarray.erase(jarray2.cbegin()), std::domain_error);
                        CHECK_THROWS_AS(jarray.erase(jarray.cbegin(), jarray2.cend()), std::domain_error);
                        CHECK_THROWS_AS(jarray.erase(jarray2.cbegin(), jarray.cend()), std::domain_error);
                        CHECK_THROWS_AS(jarray.erase(jarray2.cbegin(), jarray2.cend()), std::domain_error);

                        CHECK_THROWS_WITH(jarray.erase(jarray2.cbegin()), "iterator does not fit current value");
                        CHECK_THROWS_WITH(jarray.erase(jarray.cbegin(), jarray2.cend()),
                                          "iterators do not fit current value");
                        CHECK_THROWS_WITH(jarray.erase(jarray2.cbegin(), jarray.cend()),
                                          "iterators do not fit current value");
                        CHECK_THROWS_WITH(jarray.erase(jarray2.cbegin(), jarray2.cend()),
                                          "iterators do not fit current value");
                    }
                }
            }

            SECTION("remove element by index in non-array type")
            {
                SECTION("null")
                {
                    json j_nonobject(json::value_t::null);
                    CHECK_THROWS_AS(j_nonobject.erase(0), std::domain_error);
                    CHECK_THROWS_WITH(j_nonobject.erase(0), "cannot use erase() with null");
                }

                SECTION("boolean")
                {
                    json j_nonobject(json::value_t::boolean);
                    CHECK_THROWS_AS(j_nonobject.erase(0), std::domain_error);
                    CHECK_THROWS_WITH(j_nonobject.erase(0), "cannot use erase() with boolean");
                }

                SECTION("string")
                {
                    json j_nonobject(json::value_t::string);
                    CHECK_THROWS_AS(j_nonobject.erase(0), std::domain_error);
                    CHECK_THROWS_WITH(j_nonobject.erase(0), "cannot use erase() with string");
                }

                SECTION("object")
                {
                    json j_nonobject(json::value_t::object);
                    CHECK_THROWS_AS(j_nonobject.erase(0), std::domain_error);
                    CHECK_THROWS_WITH(j_nonobject.erase(0), "cannot use erase() with object");
                }

                SECTION("number (integer)")
                {
                    json j_nonobject(json::value_t::number_integer);
                    CHECK_THROWS_AS(j_nonobject.erase(0), std::domain_error);
                    CHECK_THROWS_WITH(j_nonobject.erase(0), "cannot use erase() with number");
                }

                SECTION("number (unsigned)")
                {
                    json j_nonobject(json::value_t::number_unsigned);
                    CHECK_THROWS_AS(j_nonobject.erase(0), std::domain_error);
                    CHECK_THROWS_WITH(j_nonobject.erase(0), "cannot use erase() with number");
                }

                SECTION("number (floating-point)")
                {
                    json j_nonobject(json::value_t::number_float);
                    CHECK_THROWS_AS(j_nonobject.erase(0), std::domain_error);
                    CHECK_THROWS_WITH(j_nonobject.erase(0), "cannot use erase() with number");
                }
            }
        }
    }

    SECTION("object")
    {
        json j = {{"integer", 1}, {"unsigned", 1u}, {"floating", 42.23}, {"null", nullptr}, {"string", "hello world"}, {"boolean", true}, {"object", json::object()}, {"array", {1, 2, 3}}};
        const json j_const = j;

        SECTION("access specified element with bounds checking")
        {
            SECTION("access within bounds")
            {
                CHECK(j.at("integer") == json(1));
                CHECK(j.at("unsigned") == json(1u));
                CHECK(j.at("boolean") == json(true));
                CHECK(j.at("null") == json(nullptr));
                CHECK(j.at("string") == json("hello world"));
                CHECK(j.at("floating") == json(42.23));
                CHECK(j.at("object") == json(json::object()));
                CHECK(j.at("array") == json({1, 2, 3}));

                CHECK(j_const.at("integer") == json(1));
                CHECK(j_const.at("unsigned") == json(1u));
                CHECK(j_const.at("boolean") == json(true));
                CHECK(j_const.at("null") == json(nullptr));
                CHECK(j_const.at("string") == json("hello world"));
                CHECK(j_const.at("floating") == json(42.23));
                CHECK(j_const.at("object") == json(json::object()));
                CHECK(j_const.at("array") == json({1, 2, 3}));
            }

            SECTION("access outside bounds")
            {
                CHECK_THROWS_AS(j.at("foo"), std::out_of_range);
                CHECK_THROWS_AS(j_const.at("foo"), std::out_of_range);
                CHECK_THROWS_WITH(j.at("foo"), "key 'foo' not found");
                CHECK_THROWS_WITH(j_const.at("foo"), "key 'foo' not found");
            }

            SECTION("access on non-object type")
            {
                SECTION("null")
                {
                    json j_nonobject(json::value_t::null);
                    const json j_nonobject_const(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject.at("foo"), std::domain_error);
                    CHECK_THROWS_AS(j_nonobject_const.at("foo"), std::domain_error);
                    CHECK_THROWS_WITH(j_nonobject.at("foo"), "cannot use at() with null");
                    CHECK_THROWS_WITH(j_nonobject_const.at("foo"), "cannot use at() with null");
                }

                SECTION("boolean")
                {
                    json j_nonobject(json::value_t::boolean);
                    const json j_nonobject_const(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject.at("foo"), std::domain_error);
                    CHECK_THROWS_AS(j_nonobject_const.at("foo"), std::domain_error);
                    CHECK_THROWS_WITH(j_nonobject.at("foo"), "cannot use at() with boolean");
                    CHECK_THROWS_WITH(j_nonobject_const.at("foo"), "cannot use at() with boolean");
                }

                SECTION("string")
                {
                    json j_nonobject(json::value_t::string);
                    const json j_nonobject_const(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject.at("foo"), std::domain_error);
                    CHECK_THROWS_AS(j_nonobject_const.at("foo"), std::domain_error);
                    CHECK_THROWS_WITH(j_nonobject.at("foo"), "cannot use at() with string");
                    CHECK_THROWS_WITH(j_nonobject_const.at("foo"), "cannot use at() with string");
                }

                SECTION("array")
                {
                    json j_nonobject(json::value_t::array);
                    const json j_nonobject_const(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject.at("foo"), std::domain_error);
                    CHECK_THROWS_AS(j_nonobject_const.at("foo"), std::domain_error);
                    CHECK_THROWS_WITH(j_nonobject.at("foo"), "cannot use at() with array");
                    CHECK_THROWS_WITH(j_nonobject_const.at("foo"), "cannot use at() with array");
                }

                SECTION("number (integer)")
                {
                    json j_nonobject(json::value_t::number_integer);
                    const json j_nonobject_const(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject.at("foo"), std::domain_error);
                    CHECK_THROWS_AS(j_nonobject_const.at("foo"), std::domain_error);
                    CHECK_THROWS_WITH(j_nonobject.at("foo"), "cannot use at() with number");
                    CHECK_THROWS_WITH(j_nonobject_const.at("foo"), "cannot use at() with number");
                }

                SECTION("number (unsigned)")
                {
                    json j_nonobject(json::value_t::number_unsigned);
                    const json j_nonobject_const(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject.at("foo"), std::domain_error);
                    CHECK_THROWS_AS(j_nonobject_const.at("foo"), std::domain_error);
                    CHECK_THROWS_WITH(j_nonobject.at("foo"), "cannot use at() with number");
                    CHECK_THROWS_WITH(j_nonobject_const.at("foo"), "cannot use at() with number");
                }

                SECTION("number (floating-point)")
                {
                    json j_nonobject(json::value_t::number_float);
                    const json j_nonobject_const(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject.at("foo"), std::domain_error);
                    CHECK_THROWS_AS(j_nonobject_const.at("foo"), std::domain_error);
                    CHECK_THROWS_WITH(j_nonobject.at("foo"), "cannot use at() with number");
                    CHECK_THROWS_WITH(j_nonobject_const.at("foo"), "cannot use at() with number");
                }
            }
        }

        SECTION("access specified element with default value")
        {
            SECTION("given a key")
            {
                SECTION("access existing value")
                {
                    CHECK(j.value("integer", 2) == 1);
                    CHECK(j.value("integer", 1.0) == Approx(1));
                    CHECK(j.value("unsigned", 2) == 1u);
                    CHECK(j.value("unsigned", 1.0) == Approx(1u));
                    CHECK(j.value("null", json(1)) == json());
                    CHECK(j.value("boolean", false) == true);
                    CHECK(j.value("string", "bar") == "hello world");
                    CHECK(j.value("string", std::string("bar")) == "hello world");
                    CHECK(j.value("floating", 12.34) == Approx(42.23));
                    CHECK(j.value("floating", 12) == 42);
                    CHECK(j.value("object", json({{"foo", "bar"}})) == json(json::object()));
                    CHECK(j.value("array", json({10, 100})) == json({1, 2, 3}));

                    CHECK(j_const.value("integer", 2) == 1);
                    CHECK(j_const.value("integer", 1.0) == Approx(1));
                    CHECK(j_const.value("unsigned", 2) == 1u);
                    CHECK(j_const.value("unsigned", 1.0) == Approx(1u));
                    CHECK(j_const.value("boolean", false) == true);
                    CHECK(j_const.value("string", "bar") == "hello world");
                    CHECK(j_const.value("string", std::string("bar")) == "hello world");
                    CHECK(j_const.value("floating", 12.34) == Approx(42.23));
                    CHECK(j_const.value("floating", 12) == 42);
                    CHECK(j_const.value("object", json({{"foo", "bar"}})) == json(json::object()));
                    CHECK(j_const.value("array", json({10, 100})) == json({1, 2, 3}));
                }

                SECTION("access non-existing value")
                {
                    CHECK(j.value("_", 2) == 2);
                    CHECK(j.value("_", 2u) == 2u);
                    CHECK(j.value("_", false) == false);
                    CHECK(j.value("_", "bar") == "bar");
                    CHECK(j.value("_", 12.34) == Approx(12.34));
                    CHECK(j.value("_", json({{"foo", "bar"}})) == json({{"foo", "bar"}}));
                    CHECK(j.value("_", json({10, 100})) == json({10, 100}));

                    CHECK(j_const.value("_", 2) == 2);
                    CHECK(j_const.value("_", 2u) == 2u);
                    CHECK(j_const.value("_", false) == false);
                    CHECK(j_const.value("_", "bar") == "bar");
                    CHECK(j_const.value("_", 12.34) == Approx(12.34));
                    CHECK(j_const.value("_", json({{"foo", "bar"}})) == json({{"foo", "bar"}}));
                    CHECK(j_const.value("_", json({10, 100})) == json({10, 100}));
                }

                SECTION("access on non-object type")
                {
                    SECTION("null")
                    {
                        json j_nonobject(json::value_t::null);
                        const json j_nonobject_const(j_nonobject);
                        CHECK_THROWS_AS(j_nonobject.value("foo", 1), std::domain_error);
                        CHECK_THROWS_AS(j_nonobject_const.value("foo", 1), std::domain_error);
                        CHECK_THROWS_WITH(j_nonobject.value("foo", 1), "cannot use value() with null");
                        CHECK_THROWS_WITH(j_nonobject_const.value("foo", 1), "cannot use value() with null");
                    }

                    SECTION("boolean")
                    {
                        json j_nonobject(json::value_t::boolean);
                        const json j_nonobject_const(j_nonobject);
                        CHECK_THROWS_AS(j_nonobject.value("foo", 1), std::domain_error);
                        CHECK_THROWS_AS(j_nonobject_const.value("foo", 1), std::domain_error);
                        CHECK_THROWS_WITH(j_nonobject.value("foo", 1), "cannot use value() with boolean");
                        CHECK_THROWS_WITH(j_nonobject_const.value("foo", 1), "cannot use value() with boolean");
                    }

                    SECTION("string")
                    {
                        json j_nonobject(json::value_t::string);
                        const json j_nonobject_const(j_nonobject);
                        CHECK_THROWS_AS(j_nonobject.value("foo", 1), std::domain_error);
                        CHECK_THROWS_AS(j_nonobject_const.value("foo", 1), std::domain_error);
                        CHECK_THROWS_WITH(j_nonobject.value("foo", 1), "cannot use value() with string");
                        CHECK_THROWS_WITH(j_nonobject_const.value("foo", 1), "cannot use value() with string");
                    }

                    SECTION("array")
                    {
                        json j_nonobject(json::value_t::array);
                        const json j_nonobject_const(j_nonobject);
                        CHECK_THROWS_AS(j_nonobject.value("foo", 1), std::domain_error);
                        CHECK_THROWS_AS(j_nonobject_const.value("foo", 1), std::domain_error);
                        CHECK_THROWS_WITH(j_nonobject.value("foo", 1), "cannot use value() with array");
                        CHECK_THROWS_WITH(j_nonobject_const.value("foo", 1), "cannot use value() with array");
                    }

                    SECTION("number (integer)")
                    {
                        json j_nonobject(json::value_t::number_integer);
                        const json j_nonobject_const(j_nonobject);
                        CHECK_THROWS_AS(j_nonobject.value("foo", 1), std::domain_error);
                        CHECK_THROWS_AS(j_nonobject_const.value("foo", 1), std::domain_error);
                        CHECK_THROWS_WITH(j_nonobject.value("foo", 1), "cannot use value() with number");
                        CHECK_THROWS_WITH(j_nonobject_const.value("foo", 1), "cannot use value() with number");
                    }

                    SECTION("number (unsigned)")
                    {
                        json j_nonobject(json::value_t::number_unsigned);
                        const json j_nonobject_const(j_nonobject);
                        CHECK_THROWS_AS(j_nonobject.value("foo", 1), std::domain_error);
                        CHECK_THROWS_AS(j_nonobject_const.value("foo", 1), std::domain_error);
                        CHECK_THROWS_WITH(j_nonobject.value("foo", 1), "cannot use value() with number");
                        CHECK_THROWS_WITH(j_nonobject_const.value("foo", 1), "cannot use value() with number");
                    }

                    SECTION("number (floating-point)")
                    {
                        json j_nonobject(json::value_t::number_float);
                        const json j_nonobject_const(j_nonobject);
                        CHECK_THROWS_AS(j_nonobject.value("foo", 1), std::domain_error);
                        CHECK_THROWS_AS(j_nonobject_const.value("foo", 1), std::domain_error);
                        CHECK_THROWS_WITH(j_nonobject.value("foo", 1), "cannot use value() with number");
                        CHECK_THROWS_WITH(j_nonobject_const.value("foo", 1), "cannot use value() with number");
                    }
                }
            }

            SECTION("given a JSON pointer")
            {
                SECTION("access existing value")
                {
                    CHECK(j.value("/integer"_json_pointer, 2) == 1);
                    CHECK(j.value("/integer"_json_pointer, 1.0) == Approx(1));
                    CHECK(j.value("/unsigned"_json_pointer, 2) == 1u);
                    CHECK(j.value("/unsigned"_json_pointer, 1.0) == Approx(1u));
                    CHECK(j.value("/null"_json_pointer, json(1)) == json());
                    CHECK(j.value("/boolean"_json_pointer, false) == true);
                    CHECK(j.value("/string"_json_pointer, "bar") == "hello world");
                    CHECK(j.value("/string"_json_pointer, std::string("bar")) == "hello world");
                    CHECK(j.value("/floating"_json_pointer, 12.34) == Approx(42.23));
                    CHECK(j.value("/floating"_json_pointer, 12) == 42);
                    CHECK(j.value("/object"_json_pointer, json({{"foo", "bar"}})) == json(json::object()));
                    CHECK(j.value("/array"_json_pointer, json({10, 100})) == json({1, 2, 3}));

                    CHECK(j_const.value("/integer"_json_pointer, 2) == 1);
                    CHECK(j_const.value("/integer"_json_pointer, 1.0) == Approx(1));
                    CHECK(j_const.value("/unsigned"_json_pointer, 2) == 1u);
                    CHECK(j_const.value("/unsigned"_json_pointer, 1.0) == Approx(1u));
                    CHECK(j_const.value("/boolean"_json_pointer, false) == true);
                    CHECK(j_const.value("/string"_json_pointer, "bar") == "hello world");
                    CHECK(j_const.value("/string"_json_pointer, std::string("bar")) == "hello world");
                    CHECK(j_const.value("/floating"_json_pointer, 12.34) == Approx(42.23));
                    CHECK(j_const.value("/floating"_json_pointer, 12) == 42);
                    CHECK(j_const.value("/object"_json_pointer, json({{"foo", "bar"}})) == json(json::object()));
                    CHECK(j_const.value("/array"_json_pointer, json({10, 100})) == json({1, 2, 3}));
                }

                SECTION("access non-existing value")
                {
                    CHECK(j.value("/not/existing"_json_pointer, 2) == 2);
                    CHECK(j.value("/not/existing"_json_pointer, 2u) == 2u);
                    CHECK(j.value("/not/existing"_json_pointer, false) == false);
                    CHECK(j.value("/not/existing"_json_pointer, "bar") == "bar");
                    CHECK(j.value("/not/existing"_json_pointer, 12.34) == Approx(12.34));
                    CHECK(j.value("/not/existing"_json_pointer, json({{"foo", "bar"}})) == json({{"foo", "bar"}}));
                    CHECK(j.value("/not/existing"_json_pointer, json({10, 100})) == json({10, 100}));

                    CHECK(j_const.value("/not/existing"_json_pointer, 2) == 2);
                    CHECK(j_const.value("/not/existing"_json_pointer, 2u) == 2u);
                    CHECK(j_const.value("/not/existing"_json_pointer, false) == false);
                    CHECK(j_const.value("/not/existing"_json_pointer, "bar") == "bar");
                    CHECK(j_const.value("/not/existing"_json_pointer, 12.34) == Approx(12.34));
                    CHECK(j_const.value("/not/existing"_json_pointer, json({{"foo", "bar"}})) == json({{"foo", "bar"}}));
                    CHECK(j_const.value("/not/existing"_json_pointer, json({10, 100})) == json({10, 100}));
                }

                SECTION("access on non-object type")
                {
                    SECTION("null")
                    {
                        json j_nonobject(json::value_t::null);
                        const json j_nonobject_const(j_nonobject);
                        CHECK_THROWS_AS(j_nonobject.value("/foo"_json_pointer, 1), std::domain_error);
                        CHECK_THROWS_AS(j_nonobject_const.value("/foo"_json_pointer, 1), std::domain_error);
                        CHECK_THROWS_WITH(j_nonobject.value("/foo"_json_pointer, 1), "cannot use value() with null");
                        CHECK_THROWS_WITH(j_nonobject_const.value("/foo"_json_pointer, 1), "cannot use value() with null");
                    }

                    SECTION("boolean")
                    {
                        json j_nonobject(json::value_t::boolean);
                        const json j_nonobject_const(j_nonobject);
                        CHECK_THROWS_AS(j_nonobject.value("/foo"_json_pointer, 1), std::domain_error);
                        CHECK_THROWS_AS(j_nonobject_const.value("/foo"_json_pointer, 1), std::domain_error);
                        CHECK_THROWS_WITH(j_nonobject.value("/foo"_json_pointer, 1), "cannot use value() with boolean");
                        CHECK_THROWS_WITH(j_nonobject_const.value("/foo"_json_pointer, 1),
                                          "cannot use value() with boolean");
                    }

                    SECTION("string")
                    {
                        json j_nonobject(json::value_t::string);
                        const json j_nonobject_const(j_nonobject);
                        CHECK_THROWS_AS(j_nonobject.value("/foo"_json_pointer, 1), std::domain_error);
                        CHECK_THROWS_AS(j_nonobject_const.value("/foo"_json_pointer, 1), std::domain_error);
                        CHECK_THROWS_WITH(j_nonobject.value("/foo"_json_pointer, 1), "cannot use value() with string");
                        CHECK_THROWS_WITH(j_nonobject_const.value("/foo"_json_pointer, 1),
                                          "cannot use value() with string");
                    }

                    SECTION("array")
                    {
                        json j_nonobject(json::value_t::array);
                        const json j_nonobject_const(j_nonobject);
                        CHECK_THROWS_AS(j_nonobject.value("/foo"_json_pointer, 1), std::domain_error);
                        CHECK_THROWS_AS(j_nonobject_const.value("/foo"_json_pointer, 1), std::domain_error);
                        CHECK_THROWS_WITH(j_nonobject.value("/foo"_json_pointer, 1), "cannot use value() with array");
                        CHECK_THROWS_WITH(j_nonobject_const.value("/foo"_json_pointer, 1), "cannot use value() with array");
                    }

                    SECTION("number (integer)")
                    {
                        json j_nonobject(json::value_t::number_integer);
                        const json j_nonobject_const(j_nonobject);
                        CHECK_THROWS_AS(j_nonobject.value("/foo"_json_pointer, 1), std::domain_error);
                        CHECK_THROWS_AS(j_nonobject_const.value("/foo"_json_pointer, 1), std::domain_error);
                        CHECK_THROWS_WITH(j_nonobject.value("/foo"_json_pointer, 1), "cannot use value() with number");
                        CHECK_THROWS_WITH(j_nonobject_const.value("/foo"_json_pointer, 1),
                                          "cannot use value() with number");
                    }

                    SECTION("number (unsigned)")
                    {
                        json j_nonobject(json::value_t::number_unsigned);
                        const json j_nonobject_const(j_nonobject);
                        CHECK_THROWS_AS(j_nonobject.value("/foo"_json_pointer, 1), std::domain_error);
                        CHECK_THROWS_AS(j_nonobject_const.value("/foo"_json_pointer, 1), std::domain_error);
                        CHECK_THROWS_WITH(j_nonobject.value("/foo"_json_pointer, 1), "cannot use value() with number");
                        CHECK_THROWS_WITH(j_nonobject_const.value("/foo"_json_pointer, 1),
                                          "cannot use value() with number");
                    }

                    SECTION("number (floating-point)")
                    {
                        json j_nonobject(json::value_t::number_float);
                        const json j_nonobject_const(j_nonobject);
                        CHECK_THROWS_AS(j_nonobject.value("/foo"_json_pointer, 1), std::domain_error);
                        CHECK_THROWS_AS(j_nonobject_const.value("/foo"_json_pointer, 1), std::domain_error);
                        CHECK_THROWS_WITH(j_nonobject.value("/foo"_json_pointer, 1), "cannot use value() with number");
                        CHECK_THROWS_WITH(j_nonobject_const.value("/foo"_json_pointer, 1),
                                          "cannot use value() with number");
                    }
                }
            }
        }

        SECTION("front and back")
        {
            // "array" is the smallest key
            CHECK(j.front() == json({1, 2, 3}));
            CHECK(j_const.front() == json({1, 2, 3}));
            // "unsigned" is the largest key
            CHECK(j.back() == json(1u));
            CHECK(j_const.back() == json(1u));
        }

        SECTION("access specified element")
        {
            SECTION("access within bounds")
            {
                CHECK(j["integer"] == json(1));
                CHECK(j[json::object_t::key_type("integer")] == j["integer"]);

                CHECK(j["unsigned"] == json(1u));
                CHECK(j[json::object_t::key_type("unsigned")] == j["unsigned"]);

                CHECK(j["boolean"] == json(true));
                CHECK(j[json::object_t::key_type("boolean")] == j["boolean"]);

                CHECK(j["null"] == json(nullptr));
                CHECK(j[json::object_t::key_type("null")] == j["null"]);

                CHECK(j["string"] == json("hello world"));
                CHECK(j[json::object_t::key_type("string")] == j["string"]);

                CHECK(j["floating"] == json(42.23));
                CHECK(j[json::object_t::key_type("floating")] == j["floating"]);

                CHECK(j["object"] == json(json::object()));
                CHECK(j[json::object_t::key_type("object")] == j["object"]);

                CHECK(j["array"] == json({1, 2, 3}));
                CHECK(j[json::object_t::key_type("array")] == j["array"]);

                CHECK(j_const["integer"] == json(1));
                CHECK(j_const[json::object_t::key_type("integer")] == j["integer"]);

                CHECK(j_const["boolean"] == json(true));
                CHECK(j_const[json::object_t::key_type("boolean")] == j["boolean"]);

                CHECK(j_const["null"] == json(nullptr));
                CHECK(j_const[json::object_t::key_type("null")] == j["null"]);

                CHECK(j_const["string"] == json("hello world"));
                CHECK(j_const[json::object_t::key_type("string")] == j["string"]);

                CHECK(j_const["floating"] == json(42.23));
                CHECK(j_const[json::object_t::key_type("floating")] == j["floating"]);

                CHECK(j_const["object"] == json(json::object()));
                CHECK(j_const[json::object_t::key_type("object")] == j["object"]);

                CHECK(j_const["array"] == json({1, 2, 3}));
                CHECK(j_const[json::object_t::key_type("array")] == j["array"]);
            }

            SECTION("access on non-object type")
            {
                SECTION("null")
                {
                    json j_nonobject(json::value_t::null);
                    json j_nonobject2(json::value_t::null);
                    const json j_const_nonobject(j_nonobject);
                    CHECK_NOTHROW(j_nonobject["foo"]);
                    CHECK_NOTHROW(j_nonobject2[json::object_t::key_type("foo")]);
                    CHECK_THROWS_AS(j_const_nonobject["foo"], std::domain_error);
                    CHECK_THROWS_AS(j_const_nonobject[json::object_t::key_type("foo")], std::domain_error);
                    CHECK_THROWS_WITH(j_const_nonobject["foo"], "cannot use operator[] with null");
                    CHECK_THROWS_WITH(j_const_nonobject[json::object_t::key_type("foo")],
                                      "cannot use operator[] with null");
                }

                SECTION("boolean")
                {
                    json j_nonobject(json::value_t::boolean);
                    const json j_const_nonobject(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject["foo"], std::domain_error);
                    CHECK_THROWS_AS(j_nonobject[json::object_t::key_type("foo")], std::domain_error);
                    CHECK_THROWS_AS(j_const_nonobject["foo"], std::domain_error);
                    CHECK_THROWS_AS(j_const_nonobject[json::object_t::key_type("foo")], std::domain_error);
                    CHECK_THROWS_WITH(j_nonobject["foo"], "cannot use operator[] with boolean");
                    CHECK_THROWS_WITH(j_nonobject[json::object_t::key_type("foo")],
                                      "cannot use operator[] with boolean");
                    CHECK_THROWS_WITH(j_const_nonobject["foo"], "cannot use operator[] with boolean");
                    CHECK_THROWS_WITH(j_const_nonobject[json::object_t::key_type("foo")],
                                      "cannot use operator[] with boolean");
                }

                SECTION("string")
                {
                    json j_nonobject(json::value_t::string);
                    const json j_const_nonobject(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject["foo"], std::domain_error);
                    CHECK_THROWS_AS(j_nonobject[json::object_t::key_type("foo")], std::domain_error);
                    CHECK_THROWS_AS(j_const_nonobject["foo"], std::domain_error);
                    CHECK_THROWS_AS(j_const_nonobject[json::object_t::key_type("foo")], std::domain_error);
                    CHECK_THROWS_WITH(j_nonobject["foo"], "cannot use operator[] with string");
                    CHECK_THROWS_WITH(j_nonobject[json::object_t::key_type("foo")],
                                      "cannot use operator[] with string");
                    CHECK_THROWS_WITH(j_const_nonobject["foo"], "cannot use operator[] with string");
                    CHECK_THROWS_WITH(j_const_nonobject[json::object_t::key_type("foo")],
                                      "cannot use operator[] with string");
                }

                SECTION("array")
                {
                    json j_nonobject(json::value_t::array);
                    const json j_const_nonobject(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject["foo"], std::domain_error);
                    CHECK_THROWS_AS(j_nonobject[json::object_t::key_type("foo")], std::domain_error);
                    CHECK_THROWS_AS(j_const_nonobject["foo"], std::domain_error);
                    CHECK_THROWS_AS(j_const_nonobject[json::object_t::key_type("foo")], std::domain_error);
                    CHECK_THROWS_WITH(j_nonobject["foo"], "cannot use operator[] with array");
                    CHECK_THROWS_WITH(j_nonobject[json::object_t::key_type("foo")], "cannot use operator[] with array");
                    CHECK_THROWS_WITH(j_const_nonobject["foo"], "cannot use operator[] with array");
                    CHECK_THROWS_WITH(j_const_nonobject[json::object_t::key_type("foo")],
                                      "cannot use operator[] with array");
                }

                SECTION("number (integer)")
                {
                    json j_nonobject(json::value_t::number_integer);
                    const json j_const_nonobject(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject["foo"], std::domain_error);
                    CHECK_THROWS_AS(j_nonobject[json::object_t::key_type("foo")], std::domain_error);
                    CHECK_THROWS_AS(j_const_nonobject["foo"], std::domain_error);
                    CHECK_THROWS_AS(j_const_nonobject[json::object_t::key_type("foo")], std::domain_error);
                    CHECK_THROWS_WITH(j_nonobject["foo"], "cannot use operator[] with number");
                    CHECK_THROWS_WITH(j_nonobject[json::object_t::key_type("foo")],
                                      "cannot use operator[] with number");
                    CHECK_THROWS_WITH(j_const_nonobject["foo"], "cannot use operator[] with number");
                    CHECK_THROWS_WITH(j_const_nonobject[json::object_t::key_type("foo")],
                                      "cannot use operator[] with number");
                }

                SECTION("number (unsigned)")
                {
                    json j_nonobject(json::value_t::number_unsigned);
                    const json j_const_nonobject(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject["foo"], std::domain_error);
                    CHECK_THROWS_AS(j_nonobject[json::object_t::key_type("foo")], std::domain_error);
                    CHECK_THROWS_AS(j_const_nonobject["foo"], std::domain_error);
                    CHECK_THROWS_AS(j_const_nonobject[json::object_t::key_type("foo")], std::domain_error);
                    CHECK_THROWS_WITH(j_nonobject["foo"], "cannot use operator[] with number");
                    CHECK_THROWS_WITH(j_nonobject[json::object_t::key_type("foo")],
                                      "cannot use operator[] with number");
                    CHECK_THROWS_WITH(j_const_nonobject["foo"], "cannot use operator[] with number");
                    CHECK_THROWS_WITH(j_const_nonobject[json::object_t::key_type("foo")],
                                      "cannot use operator[] with number");
                }

                SECTION("number (floating-point)")
                {
                    json j_nonobject(json::value_t::number_float);
                    const json j_const_nonobject(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject["foo"], std::domain_error);
                    CHECK_THROWS_AS(j_nonobject[json::object_t::key_type("foo")], std::domain_error);
                    CHECK_THROWS_AS(j_const_nonobject["foo"], std::domain_error);
                    CHECK_THROWS_AS(j_const_nonobject[json::object_t::key_type("foo")], std::domain_error);
                    CHECK_THROWS_WITH(j_nonobject["foo"], "cannot use operator[] with number");
                    CHECK_THROWS_WITH(j_nonobject[json::object_t::key_type("foo")],
                                      "cannot use operator[] with number");
                    CHECK_THROWS_WITH(j_const_nonobject["foo"], "cannot use operator[] with number");
                    CHECK_THROWS_WITH(j_const_nonobject[json::object_t::key_type("foo")],
                                      "cannot use operator[] with number");
                }
            }
        }

        SECTION("remove specified element")
        {
            SECTION("remove element by key")
            {
                CHECK(j.find("integer") != j.end());
                CHECK(j.erase("integer") == 1);
                CHECK(j.find("integer") == j.end());
                CHECK(j.erase("integer") == 0);

                CHECK(j.find("unsigned") != j.end());
                CHECK(j.erase("unsigned") == 1);
                CHECK(j.find("unsigned") == j.end());
                CHECK(j.erase("unsigned") == 0);

                CHECK(j.find("boolean") != j.end());
                CHECK(j.erase("boolean") == 1);
                CHECK(j.find("boolean") == j.end());
                CHECK(j.erase("boolean") == 0);

                CHECK(j.find("null") != j.end());
                CHECK(j.erase("null") == 1);
                CHECK(j.find("null") == j.end());
                CHECK(j.erase("null") == 0);

                CHECK(j.find("string") != j.end());
                CHECK(j.erase("string") == 1);
                CHECK(j.find("string") == j.end());
                CHECK(j.erase("string") == 0);

                CHECK(j.find("floating") != j.end());
                CHECK(j.erase("floating") == 1);
                CHECK(j.find("floating") == j.end());
                CHECK(j.erase("floating") == 0);

                CHECK(j.find("object") != j.end());
                CHECK(j.erase("object") == 1);
                CHECK(j.find("object") == j.end());
                CHECK(j.erase("object") == 0);

                CHECK(j.find("array") != j.end());
                CHECK(j.erase("array") == 1);
                CHECK(j.find("array") == j.end());
                CHECK(j.erase("array") == 0);
            }

            SECTION("remove element by iterator")
            {
                SECTION("erase(begin())")
                {
                    {
                        json jobject = {{"a", "a"}, {"b", 1}, {"c", 17u}};
                        json::iterator it2 = jobject.erase(jobject.begin());
                        CHECK(jobject == json({{"b", 1}, {"c", 17u}}));
                        CHECK(*it2 == json(1));
                    }
                    {
                        json jobject = {{"a", "a"}, {"b", 1}, {"c", 17u}};
                        json::const_iterator it2 = jobject.erase(jobject.cbegin());
                        CHECK(jobject == json({{"b", 1}, {"c", 17u}}));
                        CHECK(*it2 == json(1));
                    }
                }

                SECTION("erase(begin(), end())")
                {
                    {
                        json jobject = {{"a", "a"}, {"b", 1}, {"c", 17u}};
                        json::iterator it2 = jobject.erase(jobject.begin(), jobject.end());
                        CHECK(jobject == json::object());
                        CHECK(it2 == jobject.end());
                    }
                    {
                        json jobject = {{"a", "a"}, {"b", 1}, {"c", 17u}};
                        json::const_iterator it2 = jobject.erase(jobject.cbegin(), jobject.cend());
                        CHECK(jobject == json::object());
                        CHECK(it2 == jobject.cend());
                    }
                }

                SECTION("erase(begin(), begin())")
                {
                    {
                        json jobject = {{"a", "a"}, {"b", 1}, {"c", 17u}};
                        json::iterator it2 = jobject.erase(jobject.begin(), jobject.begin());
                        CHECK(jobject == json({{"a", "a"}, {"b", 1}, {"c", 17u}}));
                        CHECK(*it2 == json("a"));
                    }
                    {
                        json jobject = {{"a", "a"}, {"b", 1}, {"c", 17u}};
                        json::const_iterator it2 = jobject.erase(jobject.cbegin(), jobject.cbegin());
                        CHECK(jobject == json({{"a", "a"}, {"b", 1}, {"c", 17u}}));
                        CHECK(*it2 == json("a"));
                    }
                }

                SECTION("erase at offset")
                {
                    {
                        json jobject = {{"a", "a"}, {"b", 1}, {"c", 17u}};
                        json::iterator it = jobject.find("b");
                        json::iterator it2 = jobject.erase(it);
                        CHECK(jobject == json({{"a", "a"}, {"c", 17u}}));
                        CHECK(*it2 == json(17));
                    }
                    {
                        json jobject = {{"a", "a"}, {"b", 1}, {"c", 17u}};
                        json::const_iterator it = jobject.find("b");
                        json::const_iterator it2 = jobject.erase(it);
                        CHECK(jobject == json({{"a", "a"}, {"c", 17u}}));
                        CHECK(*it2 == json(17));
                    }
                }

                SECTION("erase subrange")
                {
                    {
                        json jobject = {{"a", "a"}, {"b", 1}, {"c", 17u}, {"d", false}, {"e", true}};
                        json::iterator it2 = jobject.erase(jobject.find("b"), jobject.find("e"));
                        CHECK(jobject == json({{"a", "a"}, {"e", true}}));
                        CHECK(*it2 == json(true));
                    }
                    {
                        json jobject = {{"a", "a"}, {"b", 1}, {"c", 17u}, {"d", false}, {"e", true}};
                        json::const_iterator it2 = jobject.erase(jobject.find("b"), jobject.find("e"));
                        CHECK(jobject == json({{"a", "a"}, {"e", true}}));
                        CHECK(*it2 == json(true));
                    }
                }

                SECTION("different objects")
                {
                    {
                        json jobject = {{"a", "a"}, {"b", 1}, {"c", 17u}, {"d", false}, {"e", true}};
                        json jobject2 = {{"a", "a"}, {"b", 1}, {"c", 17u}};
                        CHECK_THROWS_AS(jobject.erase(jobject2.begin()), std::domain_error);
                        CHECK_THROWS_AS(jobject.erase(jobject.begin(), jobject2.end()), std::domain_error);
                        CHECK_THROWS_AS(jobject.erase(jobject2.begin(), jobject.end()), std::domain_error);
                        CHECK_THROWS_AS(jobject.erase(jobject2.begin(), jobject2.end()), std::domain_error);
                        CHECK_THROWS_WITH(jobject.erase(jobject2.begin()), "iterator does not fit current value");
                        CHECK_THROWS_WITH(jobject.erase(jobject.begin(), jobject2.end()),
                                          "iterators do not fit current value");
                        CHECK_THROWS_WITH(jobject.erase(jobject2.begin(), jobject.end()),
                                          "iterators do not fit current value");
                        CHECK_THROWS_WITH(jobject.erase(jobject2.begin(), jobject2.end()),
                                          "iterators do not fit current value");
                    }
                    {
                        json jobject = {{"a", "a"}, {"b", 1}, {"c", 17u}, {"d", false}, {"e", true}};
                        json jobject2 = {{"a", "a"}, {"b", 1}, {"c", 17u}};
                        CHECK_THROWS_AS(jobject.erase(jobject2.cbegin()), std::domain_error);
                        CHECK_THROWS_AS(jobject.erase(jobject.cbegin(), jobject2.cend()), std::domain_error);
                        CHECK_THROWS_AS(jobject.erase(jobject2.cbegin(), jobject.cend()), std::domain_error);
                        CHECK_THROWS_AS(jobject.erase(jobject2.cbegin(), jobject2.cend()), std::domain_error);
                        CHECK_THROWS_WITH(jobject.erase(jobject2.cbegin()), "iterator does not fit current value");
                        CHECK_THROWS_WITH(jobject.erase(jobject.cbegin(), jobject2.cend()),
                                          "iterators do not fit current value");
                        CHECK_THROWS_WITH(jobject.erase(jobject2.cbegin(), jobject.cend()),
                                          "iterators do not fit current value");
                        CHECK_THROWS_WITH(jobject.erase(jobject2.cbegin(), jobject2.cend()),
                                          "iterators do not fit current value");
                    }
                }
            }

            SECTION("remove element by key in non-object type")
            {
                SECTION("null")
                {
                    json j_nonobject(json::value_t::null);
                    CHECK_THROWS_AS(j_nonobject.erase("foo"), std::domain_error);
                    CHECK_THROWS_WITH(j_nonobject.erase("foo"), "cannot use erase() with null");
                }

                SECTION("boolean")
                {
                    json j_nonobject(json::value_t::boolean);
                    CHECK_THROWS_AS(j_nonobject.erase("foo"), std::domain_error);
                    CHECK_THROWS_WITH(j_nonobject.erase("foo"), "cannot use erase() with boolean");
                }

                SECTION("string")
                {
                    json j_nonobject(json::value_t::string);
                    CHECK_THROWS_AS(j_nonobject.erase("foo"), std::domain_error);
                    CHECK_THROWS_WITH(j_nonobject.erase("foo"), "cannot use erase() with string");
                }

                SECTION("array")
                {
                    json j_nonobject(json::value_t::array);
                    CHECK_THROWS_AS(j_nonobject.erase("foo"), std::domain_error);
                    CHECK_THROWS_WITH(j_nonobject.erase("foo"), "cannot use erase() with array");
                }

                SECTION("number (integer)")
                {
                    json j_nonobject(json::value_t::number_integer);
                    CHECK_THROWS_AS(j_nonobject.erase("foo"), std::domain_error);
                    CHECK_THROWS_WITH(j_nonobject.erase("foo"), "cannot use erase() with number");
                }

                SECTION("number (floating-point)")
                {
                    json j_nonobject(json::value_t::number_float);
                    CHECK_THROWS_AS(j_nonobject.erase("foo"), std::domain_error);
                    CHECK_THROWS_WITH(j_nonobject.erase("foo"), "cannot use erase() with number");
                }
            }
        }

        SECTION("find an element in an object")
        {
            SECTION("existing element")
            {
                for (auto key :
                        {"integer", "unsigned", "floating", "null", "string", "boolean", "object", "array"
                        })
                {
                    CHECK(j.find(key) != j.end());
                    CHECK(*j.find(key) == j.at(key));
                    CHECK(j_const.find(key) != j_const.end());
                    CHECK(*j_const.find(key) == j_const.at(key));
                }
            }

            SECTION("nonexisting element")
            {
                CHECK(j.find("foo") == j.end());
                CHECK(j_const.find("foo") == j_const.end());
            }

            SECTION("all types")
            {
                SECTION("null")
                {
                    json j_nonarray(json::value_t::null);
                    const json j_nonarray_const(j_nonarray);
                    CHECK(j_nonarray.find("foo") == j_nonarray.end());
                    CHECK(j_nonarray_const.find("foo") == j_nonarray_const.end());
                }

                SECTION("string")
                {
                    json j_nonarray(json::value_t::string);
                    const json j_nonarray_const(j_nonarray);
                    CHECK(j_nonarray.find("foo") == j_nonarray.end());
                    CHECK(j_nonarray_const.find("foo") == j_nonarray_const.end());
                }

                SECTION("object")
                {
                    json j_nonarray(json::value_t::object);
                    const json j_nonarray_const(j_nonarray);
                    CHECK(j_nonarray.find("foo") == j_nonarray.end());
                    CHECK(j_nonarray_const.find("foo") == j_nonarray_const.end());
                }

                SECTION("array")
                {
                    json j_nonarray(json::value_t::array);
                    const json j_nonarray_const(j_nonarray);
                    CHECK(j_nonarray.find("foo") == j_nonarray.end());
                    CHECK(j_nonarray_const.find("foo") == j_nonarray_const.end());
                }

                SECTION("boolean")
                {
                    json j_nonarray(json::value_t::boolean);
                    const json j_nonarray_const(j_nonarray);
                    CHECK(j_nonarray.find("foo") == j_nonarray.end());
                    CHECK(j_nonarray_const.find("foo") == j_nonarray_const.end());
                }

                SECTION("number (integer)")
                {
                    json j_nonarray(json::value_t::number_integer);
                    const json j_nonarray_const(j_nonarray);
                    CHECK(j_nonarray.find("foo") == j_nonarray.end());
                    CHECK(j_nonarray_const.find("foo") == j_nonarray_const.end());
                }

                SECTION("number (unsigned)")
                {
                    json j_nonarray(json::value_t::number_unsigned);
                    const json j_nonarray_const(j_nonarray);
                    CHECK(j_nonarray.find("foo") == j_nonarray.end());
                    CHECK(j_nonarray_const.find("foo") == j_nonarray_const.end());
                }

                SECTION("number (floating-point)")
                {
                    json j_nonarray(json::value_t::number_float);
                    const json j_nonarray_const(j_nonarray);
                    CHECK(j_nonarray.find("foo") == j_nonarray.end());
                    CHECK(j_nonarray_const.find("foo") == j_nonarray_const.end());
                }
            }
        }

        SECTION("count keys in an object")
        {
            SECTION("existing element")
            {
                for (auto key :
                        {"integer", "unsigned", "floating", "null", "string", "boolean", "object", "array"
                        })
                {
                    CHECK(j.count(key) == 1);
                    CHECK(j_const.count(key) == 1);
                }
            }

            SECTION("nonexisting element")
            {
                CHECK(j.count("foo") == 0);
                CHECK(j_const.count("foo") == 0);
            }

            SECTION("all types")
            {
                SECTION("null")
                {
                    json j_nonobject(json::value_t::null);
                    const json j_nonobject_const(j_nonobject);
                    CHECK(j_nonobject.count("foo") == 0);
                    CHECK(j_nonobject_const.count("foo") == 0);
                }

                SECTION("string")
                {
                    json j_nonobject(json::value_t::string);
                    const json j_nonobject_const(j_nonobject);
                    CHECK(j_nonobject.count("foo") == 0);
                    CHECK(j_nonobject_const.count("foo") == 0);
                }

                SECTION("object")
                {
                    json j_nonobject(json::value_t::object);
                    const json j_nonobject_const(j_nonobject);
                    CHECK(j_nonobject.count("foo") == 0);
                    CHECK(j_nonobject_const.count("foo") == 0);
                }

                SECTION("array")
                {
                    json j_nonobject(json::value_t::array);
                    const json j_nonobject_const(j_nonobject);
                    CHECK(j_nonobject.count("foo") == 0);
                    CHECK(j_nonobject_const.count("foo") == 0);
                }

                SECTION("boolean")
                {
                    json j_nonobject(json::value_t::boolean);
                    const json j_nonobject_const(j_nonobject);
                    CHECK(j_nonobject.count("foo") == 0);
                    CHECK(j_nonobject_const.count("foo") == 0);
                }

                SECTION("number (integer)")
                {
                    json j_nonobject(json::value_t::number_integer);
                    const json j_nonobject_const(j_nonobject);
                    CHECK(j_nonobject.count("foo") == 0);
                    CHECK(j_nonobject_const.count("foo") == 0);
                }

                SECTION("number (unsigned)")
                {
                    json j_nonobject(json::value_t::number_unsigned);
                    const json j_nonobject_const(j_nonobject);
                    CHECK(j_nonobject.count("foo") == 0);
                    CHECK(j_nonobject_const.count("foo") == 0);
                }

                SECTION("number (floating-point)")
                {
                    json j_nonobject(json::value_t::number_float);
                    const json j_nonobject_const(j_nonobject);
                    CHECK(j_nonobject.count("foo") == 0);
                    CHECK(j_nonobject_const.count("foo") == 0);
                }
            }
        }
    }

    SECTION("other values")
    {
        SECTION("front and back")
        {
            SECTION("null")
            {
                {
                    json j;
                    CHECK_THROWS_AS(j.front(), std::out_of_range);
                    CHECK_THROWS_AS(j.back(), std::out_of_range);
                    CHECK_THROWS_WITH(j.front(), "cannot get value");
                    CHECK_THROWS_WITH(j.back(), "cannot get value");
                }
                {
                    const json j{};
                    CHECK_THROWS_AS(j.front(), std::out_of_range);
                    CHECK_THROWS_AS(j.back(), std::out_of_range);
                    CHECK_THROWS_WITH(j.front(), "cannot get value");
                    CHECK_THROWS_WITH(j.back(), "cannot get value");
                }
            }

            SECTION("string")
            {
                {
                    json j = "foo";
                    CHECK(j.front() == j);
                    CHECK(j.back() == j);
                }
                {
                    const json j = "bar";
                    CHECK(j.front() == j);
                    CHECK(j.back() == j);
                }
            }

            SECTION("number (boolean)")
            {
                {
                    json j = false;
                    CHECK(j.front() == j);
                    CHECK(j.back() == j);
                }
                {
                    const json j = true;
                    CHECK(j.front() == j);
                    CHECK(j.back() == j);
                }
            }

            SECTION("number (integer)")
            {
                {
                    json j = 17;
                    CHECK(j.front() == j);
                    CHECK(j.back() == j);
                }
                {
                    const json j = 17;
                    CHECK(j.front() == j);
                    CHECK(j.back() == j);
                }
            }

            SECTION("number (unsigned)")
            {
                {
                    json j = 17u;
                    CHECK(j.front() == j);
                    CHECK(j.back() == j);
                }
                {
                    const json j = 17u;
                    CHECK(j.front() == j);
                    CHECK(j.back() == j);
                }
            }

            SECTION("number (floating point)")
            {
                {
                    json j = 23.42;
                    CHECK(j.front() == j);
                    CHECK(j.back() == j);
                }
                {
                    const json j = 23.42;
                    CHECK(j.front() == j);
                    CHECK(j.back() == j);
                }
            }
        }

        SECTION("erase with one valid iterator")
        {
            SECTION("null")
            {
                {
                    json j;
                    CHECK_THROWS_AS(j.erase(j.begin()), std::domain_error);
                    CHECK_THROWS_WITH(j.erase(j.begin()), "cannot use erase() with null");
                }
                {
                    json j;
                    CHECK_THROWS_AS(j.erase(j.cbegin()), std::domain_error);
                    CHECK_THROWS_WITH(j.erase(j.begin()), "cannot use erase() with null");
                }
            }

            SECTION("string")
            {
                {
                    json j = "foo";
                    json::iterator it = j.erase(j.begin());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
                {
                    json j = "bar";
                    json::const_iterator it = j.erase(j.cbegin());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
            }

            SECTION("number (boolean)")
            {
                {
                    json j = false;
                    json::iterator it = j.erase(j.begin());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
                {
                    json j = true;
                    json::const_iterator it = j.erase(j.cbegin());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
            }

            SECTION("number (integer)")
            {
                {
                    json j = 17;
                    json::iterator it = j.erase(j.begin());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
                {
                    json j = 17;
                    json::const_iterator it = j.erase(j.cbegin());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
            }

            SECTION("number (unsigned)")
            {
                {
                    json j = 17u;
                    json::iterator it = j.erase(j.begin());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
                {
                    json j = 17u;
                    json::const_iterator it = j.erase(j.cbegin());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
            }

            SECTION("number (floating point)")
            {
                {
                    json j = 23.42;
                    json::iterator it = j.erase(j.begin());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
                {
                    json j = 23.42;
                    json::const_iterator it = j.erase(j.cbegin());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
            }
        }

        SECTION("erase with one invalid iterator")
        {
            SECTION("string")
            {
                {
                    json j = "foo";
                    CHECK_THROWS_AS(j.erase(j.end()), std::out_of_range);
                    CHECK_THROWS_WITH(j.erase(j.end()), "iterator out of range");
                }
                {
                    json j = "bar";
                    CHECK_THROWS_AS(j.erase(j.cend()), std::out_of_range);
                    CHECK_THROWS_WITH(j.erase(j.cend()), "iterator out of range");
                }
            }

            SECTION("number (boolean)")
            {
                {
                    json j = false;
                    CHECK_THROWS_AS(j.erase(j.end()), std::out_of_range);
                    CHECK_THROWS_WITH(j.erase(j.end()), "iterator out of range");
                }
                {
                    json j = true;
                    CHECK_THROWS_AS(j.erase(j.cend()), std::out_of_range);
                    CHECK_THROWS_WITH(j.erase(j.cend()), "iterator out of range");
                }
            }

            SECTION("number (integer)")
            {
                {
                    json j = 17;
                    CHECK_THROWS_AS(j.erase(j.end()), std::out_of_range);
                    CHECK_THROWS_WITH(j.erase(j.end()), "iterator out of range");
                }
                {
                    json j = 17;
                    CHECK_THROWS_AS(j.erase(j.cend()), std::out_of_range);
                    CHECK_THROWS_WITH(j.erase(j.cend()), "iterator out of range");
                }
            }

            SECTION("number (unsigned)")
            {
                {
                    json j = 17u;
                    CHECK_THROWS_AS(j.erase(j.end()), std::out_of_range);
                    CHECK_THROWS_WITH(j.erase(j.end()), "iterator out of range");
                }
                {
                    json j = 17u;
                    CHECK_THROWS_AS(j.erase(j.cend()), std::out_of_range);
                    CHECK_THROWS_WITH(j.erase(j.cend()), "iterator out of range");
                }
            }

            SECTION("number (floating point)")
            {
                {
                    json j = 23.42;
                    CHECK_THROWS_AS(j.erase(j.end()), std::out_of_range);
                    CHECK_THROWS_WITH(j.erase(j.end()), "iterator out of range");
                }
                {
                    json j = 23.42;
                    CHECK_THROWS_AS(j.erase(j.cend()), std::out_of_range);
                    CHECK_THROWS_WITH(j.erase(j.cend()), "iterator out of range");
                }
            }
        }

        SECTION("erase with two valid iterators")
        {
            SECTION("null")
            {
                {
                    json j;
                    CHECK_THROWS_AS(j.erase(j.begin(), j.end()), std::domain_error);
                    CHECK_THROWS_WITH(j.erase(j.begin(), j.end()), "cannot use erase() with null");
                }
                {
                    json j;
                    CHECK_THROWS_AS(j.erase(j.cbegin(), j.cend()), std::domain_error);
                    CHECK_THROWS_WITH(j.erase(j.cbegin(), j.cend()), "cannot use erase() with null");
                }
            }

            SECTION("string")
            {
                {
                    json j = "foo";
                    json::iterator it = j.erase(j.begin(), j.end());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
                {
                    json j = "bar";
                    json::const_iterator it = j.erase(j.cbegin(), j.cend());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
            }

            SECTION("number (boolean)")
            {
                {
                    json j = false;
                    json::iterator it = j.erase(j.begin(), j.end());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
                {
                    json j = true;
                    json::const_iterator it = j.erase(j.cbegin(), j.cend());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
            }

            SECTION("number (integer)")
            {
                {
                    json j = 17;
                    json::iterator it = j.erase(j.begin(), j.end());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
                {
                    json j = 17;
                    json::const_iterator it = j.erase(j.cbegin(), j.cend());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
            }

            SECTION("number (unsigned)")
            {
                {
                    json j = 17u;
                    json::iterator it = j.erase(j.begin(), j.end());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
                {
                    json j = 17u;
                    json::const_iterator it = j.erase(j.cbegin(), j.cend());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
            }

            SECTION("number (floating point)")
            {
                {
                    json j = 23.42;
                    json::iterator it = j.erase(j.begin(), j.end());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
                {
                    json j = 23.42;
                    json::const_iterator it = j.erase(j.cbegin(), j.cend());
                    CHECK(j.type() == json::value_t::null);
                    CHECK(it == j.end());
                }
            }
        }

        SECTION("erase with two invalid iterators")
        {
            SECTION("string")
            {
                {
                    json j = "foo";
                    CHECK_THROWS_AS(j.erase(j.end(), j.end()), std::out_of_range);
                    CHECK_THROWS_AS(j.erase(j.begin(), j.begin()), std::out_of_range);
                    CHECK_THROWS_WITH(j.erase(j.end(), j.end()), "iterators out of range");
                    CHECK_THROWS_WITH(j.erase(j.begin(), j.begin()), "iterators out of range");
                }
                {
                    json j = "bar";
                    CHECK_THROWS_AS(j.erase(j.cend(), j.cend()), std::out_of_range);
                    CHECK_THROWS_AS(j.erase(j.cbegin(), j.cbegin()), std::out_of_range);
                    CHECK_THROWS_WITH(j.erase(j.cend(), j.cend()), "iterators out of range");
                    CHECK_THROWS_WITH(j.erase(j.cbegin(), j.cbegin()), "iterators out of range");
                }
            }

            SECTION("number (boolean)")
            {
                {
                    json j = false;
                    CHECK_THROWS_AS(j.erase(j.end(), j.end()), std::out_of_range);
                    CHECK_THROWS_AS(j.erase(j.begin(), j.begin()), std::out_of_range);
                    CHECK_THROWS_WITH(j.erase(j.end(), j.end()), "iterators out of range");
                    CHECK_THROWS_WITH(j.erase(j.begin(), j.begin()), "iterators out of range");
                }
                {
                    json j = true;
                    CHECK_THROWS_AS(j.erase(j.cend(), j.cend()), std::out_of_range);
                    CHECK_THROWS_AS(j.erase(j.cbegin(), j.cbegin()), std::out_of_range);
                    CHECK_THROWS_WITH(j.erase(j.cend(), j.cend()), "iterators out of range");
                    CHECK_THROWS_WITH(j.erase(j.cbegin(), j.cbegin()), "iterators out of range");
                }
            }

            SECTION("number (integer)")
            {
                {
                    json j = 17;
                    CHECK_THROWS_AS(j.erase(j.end(), j.end()), std::out_of_range);
                    CHECK_THROWS_AS(j.erase(j.begin(), j.begin()), std::out_of_range);
                    CHECK_THROWS_WITH(j.erase(j.end(), j.end()), "iterators out of range");
                    CHECK_THROWS_WITH(j.erase(j.begin(), j.begin()), "iterators out of range");
                }
                {
                    json j = 17;
                    CHECK_THROWS_AS(j.erase(j.cend(), j.cend()), std::out_of_range);
                    CHECK_THROWS_AS(j.erase(j.cbegin(), j.cbegin()), std::out_of_range);
                    CHECK_THROWS_WITH(j.erase(j.cend(), j.cend()), "iterators out of range");
                    CHECK_THROWS_WITH(j.erase(j.cbegin(), j.cbegin()), "iterators out of range");
                }
            }

            SECTION("number (unsigned)")
            {
                {
                    json j = 17u;
                    CHECK_THROWS_AS(j.erase(j.end(), j.end()), std::out_of_range);
                    CHECK_THROWS_AS(j.erase(j.begin(), j.begin()), std::out_of_range);
                    CHECK_THROWS_WITH(j.erase(j.end(), j.end()), "iterators out of range");
                    CHECK_THROWS_WITH(j.erase(j.begin(), j.begin()), "iterators out of range");
                }
                {
                    json j = 17u;
                    CHECK_THROWS_AS(j.erase(j.cend(), j.cend()), std::out_of_range);
                    CHECK_THROWS_AS(j.erase(j.cbegin(), j.cbegin()), std::out_of_range);
                    CHECK_THROWS_WITH(j.erase(j.cend(), j.cend()), "iterators out of range");
                    CHECK_THROWS_WITH(j.erase(j.cbegin(), j.cbegin()), "iterators out of range");
                }
            }

            SECTION("number (floating point)")
            {
                {
                    json j = 23.42;
                    CHECK_THROWS_AS(j.erase(j.end(), j.end()), std::out_of_range);
                    CHECK_THROWS_AS(j.erase(j.begin(), j.begin()), std::out_of_range);
                    CHECK_THROWS_WITH(j.erase(j.end(), j.end()), "iterators out of range");
                    CHECK_THROWS_WITH(j.erase(j.begin(), j.begin()), "iterators out of range");
                }
                {
                    json j = 23.42;
                    CHECK_THROWS_AS(j.erase(j.cend(), j.cend()), std::out_of_range);
                    CHECK_THROWS_AS(j.erase(j.cbegin(), j.cbegin()), std::out_of_range);
                    CHECK_THROWS_WITH(j.erase(j.cend(), j.cend()), "iterators out of range");
                    CHECK_THROWS_WITH(j.erase(j.cbegin(), j.cbegin()), "iterators out of range");
                }
            }
        }
    }
}
