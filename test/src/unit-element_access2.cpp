/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.9.0
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

TEST_CASE("element access 2")
{
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
                CHECK(j.at("object") == json::object());
                CHECK(j.at("array") == json({1, 2, 3}));

                CHECK(j_const.at("integer") == json(1));
                CHECK(j_const.at("unsigned") == json(1u));
                CHECK(j_const.at("boolean") == json(true));
                CHECK(j_const.at("null") == json(nullptr));
                CHECK(j_const.at("string") == json("hello world"));
                CHECK(j_const.at("floating") == json(42.23));
                CHECK(j_const.at("object") == json::object());
                CHECK(j_const.at("array") == json({1, 2, 3}));
            }

            SECTION("access outside bounds")
            {
                CHECK_THROWS_AS(j.at("foo"), json::out_of_range&);
                CHECK_THROWS_AS(j_const.at("foo"), json::out_of_range&);
                CHECK_THROWS_WITH(j.at("foo"),
                                  "[json.exception.out_of_range.403] key 'foo' not found");
                CHECK_THROWS_WITH(j_const.at("foo"),
                                  "[json.exception.out_of_range.403] key 'foo' not found");
            }

            SECTION("access on non-object type")
            {
                SECTION("null")
                {
                    json j_nonobject(json::value_t::null);
                    const json j_nonobject_const(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject.at("foo"), json::type_error&);
                    CHECK_THROWS_AS(j_nonobject_const.at("foo"), json::type_error&);
                    CHECK_THROWS_WITH(j_nonobject.at("foo"), "[json.exception.type_error.304] cannot use at() with null");
                    CHECK_THROWS_WITH(j_nonobject_const.at("foo"), "[json.exception.type_error.304] cannot use at() with null");
                }

                SECTION("boolean")
                {
                    json j_nonobject(json::value_t::boolean);
                    const json j_nonobject_const(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject.at("foo"), json::type_error&);
                    CHECK_THROWS_AS(j_nonobject_const.at("foo"), json::type_error&);
                    CHECK_THROWS_WITH(j_nonobject.at("foo"), "[json.exception.type_error.304] cannot use at() with boolean");
                    CHECK_THROWS_WITH(j_nonobject_const.at("foo"), "[json.exception.type_error.304] cannot use at() with boolean");
                }

                SECTION("string")
                {
                    json j_nonobject(json::value_t::string);
                    const json j_nonobject_const(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject.at("foo"), json::type_error&);
                    CHECK_THROWS_AS(j_nonobject_const.at("foo"), json::type_error&);
                    CHECK_THROWS_WITH(j_nonobject.at("foo"), "[json.exception.type_error.304] cannot use at() with string");
                    CHECK_THROWS_WITH(j_nonobject_const.at("foo"), "[json.exception.type_error.304] cannot use at() with string");
                }

                SECTION("array")
                {
                    json j_nonobject(json::value_t::array);
                    const json j_nonobject_const(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject.at("foo"), json::type_error&);
                    CHECK_THROWS_AS(j_nonobject_const.at("foo"), json::type_error&);
                    CHECK_THROWS_WITH(j_nonobject.at("foo"), "[json.exception.type_error.304] cannot use at() with array");
                    CHECK_THROWS_WITH(j_nonobject_const.at("foo"), "[json.exception.type_error.304] cannot use at() with array");
                }

                SECTION("number (integer)")
                {
                    json j_nonobject(json::value_t::number_integer);
                    const json j_nonobject_const(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject.at("foo"), json::type_error&);
                    CHECK_THROWS_AS(j_nonobject_const.at("foo"), json::type_error&);
                    CHECK_THROWS_WITH(j_nonobject.at("foo"), "[json.exception.type_error.304] cannot use at() with number");
                    CHECK_THROWS_WITH(j_nonobject_const.at("foo"), "[json.exception.type_error.304] cannot use at() with number");
                }

                SECTION("number (unsigned)")
                {
                    json j_nonobject(json::value_t::number_unsigned);
                    const json j_nonobject_const(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject.at("foo"), json::type_error&);
                    CHECK_THROWS_AS(j_nonobject_const.at("foo"), json::type_error&);
                    CHECK_THROWS_WITH(j_nonobject.at("foo"), "[json.exception.type_error.304] cannot use at() with number");
                    CHECK_THROWS_WITH(j_nonobject_const.at("foo"), "[json.exception.type_error.304] cannot use at() with number");
                }

                SECTION("number (floating-point)")
                {
                    json j_nonobject(json::value_t::number_float);
                    const json j_nonobject_const(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject.at("foo"), json::type_error&);
                    CHECK_THROWS_AS(j_nonobject_const.at("foo"), json::type_error&);
                    CHECK_THROWS_WITH(j_nonobject.at("foo"), "[json.exception.type_error.304] cannot use at() with number");
                    CHECK_THROWS_WITH(j_nonobject_const.at("foo"), "[json.exception.type_error.304] cannot use at() with number");
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
                    CHECK(j.value("object", json({{"foo", "bar"}})) == json::object());
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
                    CHECK(j_const.value("object", json({{"foo", "bar"}})) == json::object());
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
                        CHECK_THROWS_AS(j_nonobject.value("foo", 1), json::type_error&);
                        CHECK_THROWS_AS(j_nonobject_const.value("foo", 1), json::type_error&);
                        CHECK_THROWS_WITH(j_nonobject.value("foo", 1),
                                          "[json.exception.type_error.306] cannot use value() with null");
                        CHECK_THROWS_WITH(j_nonobject_const.value("foo", 1),
                                          "[json.exception.type_error.306] cannot use value() with null");
                    }

                    SECTION("boolean")
                    {
                        json j_nonobject(json::value_t::boolean);
                        const json j_nonobject_const(j_nonobject);
                        CHECK_THROWS_AS(j_nonobject.value("foo", 1), json::type_error&);
                        CHECK_THROWS_AS(j_nonobject_const.value("foo", 1), json::type_error&);
                        CHECK_THROWS_WITH(j_nonobject.value("foo", 1),
                                          "[json.exception.type_error.306] cannot use value() with boolean");
                        CHECK_THROWS_WITH(j_nonobject_const.value("foo", 1),
                                          "[json.exception.type_error.306] cannot use value() with boolean");
                    }

                    SECTION("string")
                    {
                        json j_nonobject(json::value_t::string);
                        const json j_nonobject_const(j_nonobject);
                        CHECK_THROWS_AS(j_nonobject.value("foo", 1), json::type_error&);
                        CHECK_THROWS_AS(j_nonobject_const.value("foo", 1), json::type_error&);
                        CHECK_THROWS_WITH(j_nonobject.value("foo", 1),
                                          "[json.exception.type_error.306] cannot use value() with string");
                        CHECK_THROWS_WITH(j_nonobject_const.value("foo", 1),
                                          "[json.exception.type_error.306] cannot use value() with string");
                    }

                    SECTION("array")
                    {
                        json j_nonobject(json::value_t::array);
                        const json j_nonobject_const(j_nonobject);
                        CHECK_THROWS_AS(j_nonobject.value("foo", 1), json::type_error&);
                        CHECK_THROWS_AS(j_nonobject_const.value("foo", 1), json::type_error&);
                        CHECK_THROWS_WITH(j_nonobject.value("foo", 1),
                                          "[json.exception.type_error.306] cannot use value() with array");
                        CHECK_THROWS_WITH(j_nonobject_const.value("foo", 1),
                                          "[json.exception.type_error.306] cannot use value() with array");
                    }

                    SECTION("number (integer)")
                    {
                        json j_nonobject(json::value_t::number_integer);
                        const json j_nonobject_const(j_nonobject);
                        CHECK_THROWS_AS(j_nonobject.value("foo", 1), json::type_error&);
                        CHECK_THROWS_AS(j_nonobject_const.value("foo", 1), json::type_error&);
                        CHECK_THROWS_WITH(j_nonobject.value("foo", 1),
                                          "[json.exception.type_error.306] cannot use value() with number");
                        CHECK_THROWS_WITH(j_nonobject_const.value("foo", 1),
                                          "[json.exception.type_error.306] cannot use value() with number");
                    }

                    SECTION("number (unsigned)")
                    {
                        json j_nonobject(json::value_t::number_unsigned);
                        const json j_nonobject_const(j_nonobject);
                        CHECK_THROWS_AS(j_nonobject.value("foo", 1), json::type_error&);
                        CHECK_THROWS_AS(j_nonobject_const.value("foo", 1), json::type_error&);
                        CHECK_THROWS_WITH(j_nonobject.value("foo", 1),
                                          "[json.exception.type_error.306] cannot use value() with number");
                        CHECK_THROWS_WITH(j_nonobject_const.value("foo", 1),
                                          "[json.exception.type_error.306] cannot use value() with number");
                    }

                    SECTION("number (floating-point)")
                    {
                        json j_nonobject(json::value_t::number_float);
                        const json j_nonobject_const(j_nonobject);
                        CHECK_THROWS_AS(j_nonobject.value("foo", 1), json::type_error&);
                        CHECK_THROWS_AS(j_nonobject_const.value("foo", 1), json::type_error&);
                        CHECK_THROWS_WITH(j_nonobject.value("foo", 1),
                                          "[json.exception.type_error.306] cannot use value() with number");
                        CHECK_THROWS_WITH(j_nonobject_const.value("foo", 1),
                                          "[json.exception.type_error.306] cannot use value() with number");
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
                    CHECK(j.value("/object"_json_pointer, json({{"foo", "bar"}})) == json::object());
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
                    CHECK(j_const.value("/object"_json_pointer, json({{"foo", "bar"}})) == json::object());
                    CHECK(j_const.value("/array"_json_pointer, json({10, 100})) == json({1, 2, 3}));
                }

                SECTION("access on non-object type")
                {
                    SECTION("null")
                    {
                        json j_nonobject(json::value_t::null);
                        const json j_nonobject_const(j_nonobject);
                        CHECK_THROWS_AS(j_nonobject.value("/foo"_json_pointer, 1), json::type_error&);
                        CHECK_THROWS_AS(j_nonobject_const.value("/foo"_json_pointer, 1), json::type_error&);
                        CHECK_THROWS_WITH(j_nonobject.value("/foo"_json_pointer, 1),
                                          "[json.exception.type_error.306] cannot use value() with null");
                        CHECK_THROWS_WITH(j_nonobject_const.value("/foo"_json_pointer, 1),
                                          "[json.exception.type_error.306] cannot use value() with null");
                    }

                    SECTION("boolean")
                    {
                        json j_nonobject(json::value_t::boolean);
                        const json j_nonobject_const(j_nonobject);
                        CHECK_THROWS_AS(j_nonobject.value("/foo"_json_pointer, 1), json::type_error&);
                        CHECK_THROWS_AS(j_nonobject_const.value("/foo"_json_pointer, 1), json::type_error&);
                        CHECK_THROWS_WITH(j_nonobject.value("/foo"_json_pointer, 1),
                                          "[json.exception.type_error.306] cannot use value() with boolean");
                        CHECK_THROWS_WITH(j_nonobject_const.value("/foo"_json_pointer, 1),
                                          "[json.exception.type_error.306] cannot use value() with boolean");
                    }

                    SECTION("string")
                    {
                        json j_nonobject(json::value_t::string);
                        const json j_nonobject_const(j_nonobject);
                        CHECK_THROWS_AS(j_nonobject.value("/foo"_json_pointer, 1), json::type_error&);
                        CHECK_THROWS_AS(j_nonobject_const.value("/foo"_json_pointer, 1), json::type_error&);
                        CHECK_THROWS_WITH(j_nonobject.value("/foo"_json_pointer, 1),
                                          "[json.exception.type_error.306] cannot use value() with string");
                        CHECK_THROWS_WITH(j_nonobject_const.value("/foo"_json_pointer, 1),
                                          "[json.exception.type_error.306] cannot use value() with string");
                    }

                    SECTION("array")
                    {
                        json j_nonobject(json::value_t::array);
                        const json j_nonobject_const(j_nonobject);
                        CHECK_THROWS_AS(j_nonobject.value("/foo"_json_pointer, 1), json::type_error&);
                        CHECK_THROWS_AS(j_nonobject_const.value("/foo"_json_pointer, 1), json::type_error&);
                        CHECK_THROWS_WITH(j_nonobject.value("/foo"_json_pointer, 1),
                                          "[json.exception.type_error.306] cannot use value() with array");
                        CHECK_THROWS_WITH(j_nonobject_const.value("/foo"_json_pointer, 1),
                                          "[json.exception.type_error.306] cannot use value() with array");
                    }

                    SECTION("number (integer)")
                    {
                        json j_nonobject(json::value_t::number_integer);
                        const json j_nonobject_const(j_nonobject);
                        CHECK_THROWS_AS(j_nonobject.value("/foo"_json_pointer, 1), json::type_error&);
                        CHECK_THROWS_AS(j_nonobject_const.value("/foo"_json_pointer, 1), json::type_error&);
                        CHECK_THROWS_WITH(j_nonobject.value("/foo"_json_pointer, 1),
                                          "[json.exception.type_error.306] cannot use value() with number");
                        CHECK_THROWS_WITH(j_nonobject_const.value("/foo"_json_pointer, 1),
                                          "[json.exception.type_error.306] cannot use value() with number");
                    }

                    SECTION("number (unsigned)")
                    {
                        json j_nonobject(json::value_t::number_unsigned);
                        const json j_nonobject_const(j_nonobject);
                        CHECK_THROWS_AS(j_nonobject.value("/foo"_json_pointer, 1), json::type_error&);
                        CHECK_THROWS_AS(j_nonobject_const.value("/foo"_json_pointer, 1), json::type_error&);
                        CHECK_THROWS_WITH(j_nonobject.value("/foo"_json_pointer, 1),
                                          "[json.exception.type_error.306] cannot use value() with number");
                        CHECK_THROWS_WITH(j_nonobject_const.value("/foo"_json_pointer, 1),
                                          "[json.exception.type_error.306] cannot use value() with number");
                    }

                    SECTION("number (floating-point)")
                    {
                        json j_nonobject(json::value_t::number_float);
                        const json j_nonobject_const(j_nonobject);
                        CHECK_THROWS_AS(j_nonobject.value("/foo"_json_pointer, 1), json::type_error&);
                        CHECK_THROWS_AS(j_nonobject_const.value("/foo"_json_pointer, 1), json::type_error&);
                        CHECK_THROWS_WITH(j_nonobject.value("/foo"_json_pointer, 1),
                                          "[json.exception.type_error.306] cannot use value() with number");
                        CHECK_THROWS_WITH(j_nonobject_const.value("/foo"_json_pointer, 1),
                                          "[json.exception.type_error.306] cannot use value() with number");
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

                CHECK(j["object"] == json::object());
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

                CHECK(j_const["object"] == json::object());
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
                    CHECK_THROWS_AS(j_const_nonobject["foo"], json::type_error&);
                    CHECK_THROWS_AS(j_const_nonobject[json::object_t::key_type("foo")], json::type_error&);
                    CHECK_THROWS_WITH(j_const_nonobject["foo"], "[json.exception.type_error.305] cannot use operator[] with a string argument with null");
                    CHECK_THROWS_WITH(j_const_nonobject[json::object_t::key_type("foo")],
                                      "[json.exception.type_error.305] cannot use operator[] with a string argument with null");
                }

                SECTION("boolean")
                {
                    json j_nonobject(json::value_t::boolean);
                    const json j_const_nonobject(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject["foo"], json::type_error&);
                    CHECK_THROWS_AS(j_nonobject[json::object_t::key_type("foo")], json::type_error&);
                    CHECK_THROWS_AS(j_const_nonobject["foo"], json::type_error&);
                    CHECK_THROWS_AS(j_const_nonobject[json::object_t::key_type("foo")], json::type_error&);
                    CHECK_THROWS_WITH(j_nonobject["foo"],
                                      "[json.exception.type_error.305] cannot use operator[] with a string argument with boolean");
                    CHECK_THROWS_WITH(j_nonobject[json::object_t::key_type("foo")],
                                      "[json.exception.type_error.305] cannot use operator[] with a string argument with boolean");
                    CHECK_THROWS_WITH(j_const_nonobject["foo"],
                                      "[json.exception.type_error.305] cannot use operator[] with a string argument with boolean");
                    CHECK_THROWS_WITH(j_const_nonobject[json::object_t::key_type("foo")],
                                      "[json.exception.type_error.305] cannot use operator[] with a string argument with boolean");
                }

                SECTION("string")
                {
                    json j_nonobject(json::value_t::string);
                    const json j_const_nonobject(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject["foo"], json::type_error&);
                    CHECK_THROWS_AS(j_nonobject[json::object_t::key_type("foo")], json::type_error&);
                    CHECK_THROWS_AS(j_const_nonobject["foo"], json::type_error&);
                    CHECK_THROWS_AS(j_const_nonobject[json::object_t::key_type("foo")], json::type_error&);
                    CHECK_THROWS_WITH(j_nonobject["foo"],
                                      "[json.exception.type_error.305] cannot use operator[] with a string argument with string");
                    CHECK_THROWS_WITH(j_nonobject[json::object_t::key_type("foo")],
                                      "[json.exception.type_error.305] cannot use operator[] with a string argument with string");
                    CHECK_THROWS_WITH(j_const_nonobject["foo"],
                                      "[json.exception.type_error.305] cannot use operator[] with a string argument with string");
                    CHECK_THROWS_WITH(j_const_nonobject[json::object_t::key_type("foo")],
                                      "[json.exception.type_error.305] cannot use operator[] with a string argument with string");
                }

                SECTION("array")
                {
                    json j_nonobject(json::value_t::array);
                    const json j_const_nonobject(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject["foo"], json::type_error&);
                    CHECK_THROWS_AS(j_nonobject[json::object_t::key_type("foo")], json::type_error&);
                    CHECK_THROWS_AS(j_const_nonobject["foo"], json::type_error&);
                    CHECK_THROWS_AS(j_const_nonobject[json::object_t::key_type("foo")], json::type_error&);
                    CHECK_THROWS_WITH(j_nonobject["foo"],
                                      "[json.exception.type_error.305] cannot use operator[] with a string argument with array");
                    CHECK_THROWS_WITH(j_nonobject[json::object_t::key_type("foo")], "[json.exception.type_error.305] cannot use operator[] with a string argument with array");
                    CHECK_THROWS_WITH(j_const_nonobject["foo"],
                                      "[json.exception.type_error.305] cannot use operator[] with a string argument with array");
                    CHECK_THROWS_WITH(j_const_nonobject[json::object_t::key_type("foo")],
                                      "[json.exception.type_error.305] cannot use operator[] with a string argument with array");
                }

                SECTION("number (integer)")
                {
                    json j_nonobject(json::value_t::number_integer);
                    const json j_const_nonobject(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject["foo"], json::type_error&);
                    CHECK_THROWS_AS(j_nonobject[json::object_t::key_type("foo")], json::type_error&);
                    CHECK_THROWS_AS(j_const_nonobject["foo"], json::type_error&);
                    CHECK_THROWS_AS(j_const_nonobject[json::object_t::key_type("foo")], json::type_error&);
                    CHECK_THROWS_WITH(j_nonobject["foo"],
                                      "[json.exception.type_error.305] cannot use operator[] with a string argument with number");
                    CHECK_THROWS_WITH(j_nonobject[json::object_t::key_type("foo")],
                                      "[json.exception.type_error.305] cannot use operator[] with a string argument with number");
                    CHECK_THROWS_WITH(j_const_nonobject["foo"],
                                      "[json.exception.type_error.305] cannot use operator[] with a string argument with number");
                    CHECK_THROWS_WITH(j_const_nonobject[json::object_t::key_type("foo")],
                                      "[json.exception.type_error.305] cannot use operator[] with a string argument with number");
                }

                SECTION("number (unsigned)")
                {
                    json j_nonobject(json::value_t::number_unsigned);
                    const json j_const_nonobject(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject["foo"], json::type_error&);
                    CHECK_THROWS_AS(j_nonobject[json::object_t::key_type("foo")], json::type_error&);
                    CHECK_THROWS_AS(j_const_nonobject["foo"], json::type_error&);
                    CHECK_THROWS_AS(j_const_nonobject[json::object_t::key_type("foo")], json::type_error&);
                    CHECK_THROWS_WITH(j_nonobject["foo"],
                                      "[json.exception.type_error.305] cannot use operator[] with a string argument with number");
                    CHECK_THROWS_WITH(j_nonobject[json::object_t::key_type("foo")],
                                      "[json.exception.type_error.305] cannot use operator[] with a string argument with number");
                    CHECK_THROWS_WITH(j_const_nonobject["foo"],
                                      "[json.exception.type_error.305] cannot use operator[] with a string argument with number");
                    CHECK_THROWS_WITH(j_const_nonobject[json::object_t::key_type("foo")],
                                      "[json.exception.type_error.305] cannot use operator[] with a string argument with number");
                }

                SECTION("number (floating-point)")
                {
                    json j_nonobject(json::value_t::number_float);
                    const json j_const_nonobject(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject["foo"], json::type_error&);
                    CHECK_THROWS_AS(j_nonobject[json::object_t::key_type("foo")], json::type_error&);
                    CHECK_THROWS_AS(j_const_nonobject["foo"], json::type_error&);
                    CHECK_THROWS_AS(j_const_nonobject[json::object_t::key_type("foo")], json::type_error&);
                    CHECK_THROWS_WITH(j_nonobject["foo"],
                                      "[json.exception.type_error.305] cannot use operator[] with a string argument with number");
                    CHECK_THROWS_WITH(j_nonobject[json::object_t::key_type("foo")],
                                      "[json.exception.type_error.305] cannot use operator[] with a string argument with number");
                    CHECK_THROWS_WITH(j_const_nonobject["foo"],
                                      "[json.exception.type_error.305] cannot use operator[] with a string argument with number");
                    CHECK_THROWS_WITH(j_const_nonobject[json::object_t::key_type("foo")],
                                      "[json.exception.type_error.305] cannot use operator[] with a string argument with number");
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
                        CHECK_THROWS_AS(jobject.erase(jobject2.begin()), json::invalid_iterator&);
                        CHECK_THROWS_AS(jobject.erase(jobject.begin(), jobject2.end()), json::invalid_iterator&);
                        CHECK_THROWS_AS(jobject.erase(jobject2.begin(), jobject.end()), json::invalid_iterator&);
                        CHECK_THROWS_AS(jobject.erase(jobject2.begin(), jobject2.end()), json::invalid_iterator&);
                        CHECK_THROWS_WITH(jobject.erase(jobject2.begin()),
                                          "[json.exception.invalid_iterator.202] iterator does not fit current value");
                        CHECK_THROWS_WITH(jobject.erase(jobject.begin(), jobject2.end()),
                                          "[json.exception.invalid_iterator.203] iterators do not fit current value");
                        CHECK_THROWS_WITH(jobject.erase(jobject2.begin(), jobject.end()),
                                          "[json.exception.invalid_iterator.203] iterators do not fit current value");
                        CHECK_THROWS_WITH(jobject.erase(jobject2.begin(), jobject2.end()),
                                          "[json.exception.invalid_iterator.203] iterators do not fit current value");
                    }
                    {
                        json jobject = {{"a", "a"}, {"b", 1}, {"c", 17u}, {"d", false}, {"e", true}};
                        json jobject2 = {{"a", "a"}, {"b", 1}, {"c", 17u}};
                        CHECK_THROWS_AS(jobject.erase(jobject2.cbegin()), json::invalid_iterator&);
                        CHECK_THROWS_AS(jobject.erase(jobject.cbegin(), jobject2.cend()), json::invalid_iterator&);
                        CHECK_THROWS_AS(jobject.erase(jobject2.cbegin(), jobject.cend()), json::invalid_iterator&);
                        CHECK_THROWS_AS(jobject.erase(jobject2.cbegin(), jobject2.cend()), json::invalid_iterator&);
                        CHECK_THROWS_WITH(jobject.erase(jobject2.cbegin()),
                                          "[json.exception.invalid_iterator.202] iterator does not fit current value");
                        CHECK_THROWS_WITH(jobject.erase(jobject.cbegin(), jobject2.cend()),
                                          "[json.exception.invalid_iterator.203] iterators do not fit current value");
                        CHECK_THROWS_WITH(jobject.erase(jobject2.cbegin(), jobject.cend()),
                                          "[json.exception.invalid_iterator.203] iterators do not fit current value");
                        CHECK_THROWS_WITH(jobject.erase(jobject2.cbegin(), jobject2.cend()),
                                          "[json.exception.invalid_iterator.203] iterators do not fit current value");
                    }
                }
            }

            SECTION("remove element by key in non-object type")
            {
                SECTION("null")
                {
                    json j_nonobject(json::value_t::null);
                    CHECK_THROWS_AS(j_nonobject.erase("foo"), json::type_error&);
                    CHECK_THROWS_WITH(j_nonobject.erase("foo"),
                                      "[json.exception.type_error.307] cannot use erase() with null");
                }

                SECTION("boolean")
                {
                    json j_nonobject(json::value_t::boolean);
                    CHECK_THROWS_AS(j_nonobject.erase("foo"), json::type_error&);
                    CHECK_THROWS_WITH(j_nonobject.erase("foo"),
                                      "[json.exception.type_error.307] cannot use erase() with boolean");
                }

                SECTION("string")
                {
                    json j_nonobject(json::value_t::string);
                    CHECK_THROWS_AS(j_nonobject.erase("foo"), json::type_error&);
                    CHECK_THROWS_WITH(j_nonobject.erase("foo"),
                                      "[json.exception.type_error.307] cannot use erase() with string");
                }

                SECTION("array")
                {
                    json j_nonobject(json::value_t::array);
                    CHECK_THROWS_AS(j_nonobject.erase("foo"), json::type_error&);
                    CHECK_THROWS_WITH(j_nonobject.erase("foo"),
                                      "[json.exception.type_error.307] cannot use erase() with array");
                }

                SECTION("number (integer)")
                {
                    json j_nonobject(json::value_t::number_integer);
                    CHECK_THROWS_AS(j_nonobject.erase("foo"), json::type_error&);
                    CHECK_THROWS_WITH(j_nonobject.erase("foo"),
                                      "[json.exception.type_error.307] cannot use erase() with number");
                }

                SECTION("number (floating-point)")
                {
                    json j_nonobject(json::value_t::number_float);
                    CHECK_THROWS_AS(j_nonobject.erase("foo"), json::type_error&);
                    CHECK_THROWS_WITH(j_nonobject.erase("foo"),
                                      "[json.exception.type_error.307] cannot use erase() with number");
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

        SECTION("check existence of key in an object")
        {
            SECTION("existing element")
            {
                for (auto key :
                        {"integer", "unsigned", "floating", "null", "string", "boolean", "object", "array"
                        })
                {
                    CHECK(j.contains(key) == true);
                    CHECK(j_const.contains(key) == true);
                }
            }

            SECTION("nonexisting element")
            {
                CHECK(j.contains("foo") == false);
                CHECK(j_const.contains("foo") == false);
            }

            SECTION("all types")
            {
                SECTION("null")
                {
                    json j_nonobject(json::value_t::null);
                    const json j_nonobject_const(j_nonobject);
                    CHECK(j_nonobject.contains("foo") == false);
                    CHECK(j_nonobject_const.contains("foo") == false);
                }

                SECTION("string")
                {
                    json j_nonobject(json::value_t::string);
                    const json j_nonobject_const(j_nonobject);
                    CHECK(j_nonobject.contains("foo") == false);
                    CHECK(j_nonobject_const.contains("foo") == false);
                }

                SECTION("object")
                {
                    json j_nonobject(json::value_t::object);
                    const json j_nonobject_const(j_nonobject);
                    CHECK(j_nonobject.contains("foo") == false);
                    CHECK(j_nonobject_const.contains("foo") == false);
                }

                SECTION("array")
                {
                    json j_nonobject(json::value_t::array);
                    const json j_nonobject_const(j_nonobject);
                    CHECK(j_nonobject.contains("foo") == false);
                    CHECK(j_nonobject_const.contains("foo") == false);
                }

                SECTION("boolean")
                {
                    json j_nonobject(json::value_t::boolean);
                    const json j_nonobject_const(j_nonobject);
                    CHECK(j_nonobject.contains("foo") == false);
                    CHECK(j_nonobject_const.contains("foo") == false);
                }

                SECTION("number (integer)")
                {
                    json j_nonobject(json::value_t::number_integer);
                    const json j_nonobject_const(j_nonobject);
                    CHECK(j_nonobject.contains("foo") == false);
                    CHECK(j_nonobject_const.contains("foo") == false);
                }

                SECTION("number (unsigned)")
                {
                    json j_nonobject(json::value_t::number_unsigned);
                    const json j_nonobject_const(j_nonobject);
                    CHECK(j_nonobject.contains("foo") == false);
                    CHECK(j_nonobject_const.contains("foo") == false);
                }

                SECTION("number (floating-point)")
                {
                    json j_nonobject(json::value_t::number_float);
                    const json j_nonobject_const(j_nonobject);
                    CHECK(j_nonobject.contains("foo") == false);
                    CHECK(j_nonobject_const.contains("foo") == false);
                }
            }
        }
    }
}

#if !defined(JSON_NOEXCEPTION)
TEST_CASE("element access 2 (throwing tests)")
{
    SECTION("object")
    {
        json j = {{"integer", 1}, {"unsigned", 1u}, {"floating", 42.23}, {"null", nullptr}, {"string", "hello world"}, {"boolean", true}, {"object", json::object()}, {"array", {1, 2, 3}}};
        const json j_const = j;

        SECTION("access specified element with default value")
        {
            SECTION("given a JSON pointer")
            {
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
            }
        }
    }
}
#endif
