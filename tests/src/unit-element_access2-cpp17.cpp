//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// This file contains the C++17-only part of unit-element_access2.cpp (lookup with
// std::string_view keys). It is kept in a separate translation unit so the (much
// larger) unit-element_access2.cpp is built for C++11 only.

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
#ifdef JSON_TEST_NO_GLOBAL_UDLS
    using namespace nlohmann::literals; // NOLINT(google-build-using-namespace)
#endif

#ifdef JSON_HAS_CPP_17
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

// see unit-element_access2.cpp; renamed to avoid clashes in unity builds
template<typename BasicJsonType, typename T>
using can_call_sv_find = decltype(std::declval<BasicJsonType>().find(std::declval<T>()));

template<typename BasicJsonType, typename T>
using can_call_sv_count = decltype(std::declval<BasicJsonType>().count(std::declval<T>()));

template<typename BasicJsonType, typename T>
using can_call_sv_contains = decltype(std::declval<BasicJsonType>().contains(std::declval<T>()));

TEST_CASE_TEMPLATE("element access 2 (C++17)", Json, nlohmann::json, nlohmann::ordered_json) // NOLINT(readability-math-missing-parentheses, bugprone-throwing-static-initialization)
{
    SECTION("object")
    {
        Json j = {{"integer", 1}, {"unsigned", 1u}, {"floating", 42.23}, {"null", nullptr}, {"string", "hello world"}, {"boolean", true}, {"object", Json::object()}, {"array", {1, 2, 3}}};
        const Json j_const = j;

        SECTION("access specified element with bounds checking")
        {
            SECTION("access within bounds")
            {
                CHECK(j.at(std::string_view("integer")) == Json(1));
                CHECK(j.at(std::string_view("unsigned")) == Json(1u));
                CHECK(j.at(std::string_view("boolean")) == Json(true));
                CHECK(j.at(std::string_view("null")) == Json(nullptr));
                CHECK(j.at(std::string_view("string")) == Json("hello world"));
                CHECK(j.at(std::string_view("floating")) == Json(42.23));
                CHECK(j.at(std::string_view("object")) == Json::object());
                CHECK(j.at(std::string_view("array")) == Json({1, 2, 3}));

                CHECK(j_const.at(std::string_view("integer")) == Json(1));
                CHECK(j_const.at(std::string_view("unsigned")) == Json(1u));
                CHECK(j_const.at(std::string_view("boolean")) == Json(true));
                CHECK(j_const.at(std::string_view("null")) == Json(nullptr));
                CHECK(j_const.at(std::string_view("string")) == Json("hello world"));
                CHECK(j_const.at(std::string_view("floating")) == Json(42.23));
                CHECK(j_const.at(std::string_view("object")) == Json::object());
                CHECK(j_const.at(std::string_view("array")) == Json({1, 2, 3}));
            }

            SECTION("access outside bounds")
            {
                CHECK_THROWS_WITH_AS(j.at(std::string_view("foo")), "[json.exception.out_of_range.403] key 'foo' not found", typename Json::out_of_range&);
                CHECK_THROWS_WITH_AS(j_const.at(std::string_view("foo")), "[json.exception.out_of_range.403] key 'foo' not found", typename Json::out_of_range&);
            }

            SECTION("access on non-object type")
            {
                SECTION("null")
                {
                    Json j_nonobject(Json::value_t::null);
                    const Json j_nonobject_const(j_nonobject); // NOLINT(performance-unnecessary-copy-initialization)

                    CHECK_THROWS_WITH_AS(j_nonobject.at(std::string_view(std::string_view("foo"))), "[json.exception.type_error.304] cannot use at() with null", typename Json::type_error&);
                    CHECK_THROWS_WITH_AS(j_nonobject_const.at(std::string_view(std::string_view("foo"))), "[json.exception.type_error.304] cannot use at() with null", typename Json::type_error&);
                }

                SECTION("boolean")
                {
                    Json j_nonobject(Json::value_t::boolean);
                    const Json j_nonobject_const(j_nonobject); // NOLINT(performance-unnecessary-copy-initialization)

                    CHECK_THROWS_WITH_AS(j_nonobject.at(std::string_view("foo")), "[json.exception.type_error.304] cannot use at() with boolean", typename Json::type_error&);
                    CHECK_THROWS_WITH_AS(j_nonobject_const.at(std::string_view("foo")), "[json.exception.type_error.304] cannot use at() with boolean", typename Json::type_error&);
                }

                SECTION("string")
                {
                    Json j_nonobject(Json::value_t::string);
                    const Json j_nonobject_const(j_nonobject); // NOLINT(performance-unnecessary-copy-initialization)

                    CHECK_THROWS_WITH_AS(j_nonobject.at(std::string_view("foo")), "[json.exception.type_error.304] cannot use at() with string", typename Json::type_error&);
                    CHECK_THROWS_WITH_AS(j_nonobject_const.at(std::string_view("foo")), "[json.exception.type_error.304] cannot use at() with string", typename Json::type_error&);
                }

                SECTION("array")
                {
                    Json j_nonobject(Json::value_t::array);
                    const Json j_nonobject_const(j_nonobject); // NOLINT(performance-unnecessary-copy-initialization)

                    CHECK_THROWS_WITH_AS(j_nonobject.at(std::string_view("foo")), "[json.exception.type_error.304] cannot use at() with array", typename Json::type_error&);
                    CHECK_THROWS_WITH_AS(j_nonobject_const.at(std::string_view("foo")), "[json.exception.type_error.304] cannot use at() with array", typename Json::type_error&);
                }

                SECTION("number (integer)")
                {
                    Json j_nonobject(Json::value_t::number_integer);
                    const Json j_nonobject_const(j_nonobject); // NOLINT(performance-unnecessary-copy-initialization)

                    CHECK_THROWS_WITH_AS(j_nonobject.at(std::string_view("foo")), "[json.exception.type_error.304] cannot use at() with number", typename Json::type_error&);
                    CHECK_THROWS_WITH_AS(j_nonobject_const.at(std::string_view("foo")), "[json.exception.type_error.304] cannot use at() with number", typename Json::type_error&);
                }

                SECTION("number (unsigned)")
                {
                    Json j_nonobject(Json::value_t::number_unsigned);
                    const Json j_nonobject_const(j_nonobject); // NOLINT(performance-unnecessary-copy-initialization)

                    CHECK_THROWS_WITH_AS(j_nonobject.at(std::string_view("foo")), "[json.exception.type_error.304] cannot use at() with number", typename Json::type_error&);
                    CHECK_THROWS_WITH_AS(j_nonobject_const.at(std::string_view("foo")), "[json.exception.type_error.304] cannot use at() with number", typename Json::type_error&);
                }

                SECTION("number (floating-point)")
                {
                    Json j_nonobject(Json::value_t::number_float);
                    const Json j_nonobject_const(j_nonobject); // NOLINT(performance-unnecessary-copy-initialization)

                    CHECK_THROWS_WITH_AS(j_nonobject.at(std::string_view("foo")), "[json.exception.type_error.304] cannot use at() with number", typename Json::type_error&);
                    CHECK_THROWS_WITH_AS(j_nonobject_const.at(std::string_view("foo")), "[json.exception.type_error.304] cannot use at() with number", typename Json::type_error&);
                }
            }
        }

        SECTION("access specified element with default value")
        {
            SECTION("given a key")
            {
                SECTION("access existing value")
                {
                    CHECK(j.value(std::string_view("integer"), 2) == 1);
                    CHECK(j.value(std::string_view("integer"), 1.0) == Approx(1));
                    CHECK(j.value(std::string_view("unsigned"), 2) == 1u);
                    CHECK(j.value(std::string_view("unsigned"), 1.0) == Approx(1u));
                    CHECK(j.value(std::string_view("null"), Json(1)) == Json());
                    CHECK(j.value(std::string_view("boolean"), false) == true);
                    CHECK(j.value(std::string_view("string"), "bar") == "hello world");
                    CHECK(j.value(std::string_view("string"), std::string("bar")) == "hello world");
                    CHECK(j.value(std::string_view("floating"), 12.34) == Approx(42.23));
                    CHECK(j.value(std::string_view("floating"), 12) == 42);
                    CHECK(j.value(std::string_view("object"), Json({{"foo", "bar"}})) == Json::object());
                    CHECK(j.value(std::string_view("array"), Json({10, 100})) == Json({1, 2, 3}));

                    CHECK(j_const.value(std::string_view("integer"), 2) == 1);
                    CHECK(j_const.value(std::string_view("integer"), 1.0) == Approx(1));
                    CHECK(j_const.value(std::string_view("unsigned"), 2) == 1u);
                    CHECK(j_const.value(std::string_view("unsigned"), 1.0) == Approx(1u));
                    CHECK(j_const.value(std::string_view("boolean"), false) == true);
                    CHECK(j_const.value(std::string_view("string"), "bar") == "hello world");
                    CHECK(j_const.value(std::string_view("string"), std::string("bar")) == "hello world");
                    CHECK(j_const.value(std::string_view("floating"), 12.34) == Approx(42.23));
                    CHECK(j_const.value(std::string_view("floating"), 12) == 42);
                    CHECK(j_const.value(std::string_view("object"), Json({{"foo", "bar"}})) == Json::object());
                    CHECK(j_const.value(std::string_view("array"), Json({10, 100})) == Json({1, 2, 3}));
                }

                SECTION("access non-existing value")
                {
                    CHECK(j.value(std::string_view("_"), 2) == 2);
                    CHECK(j.value(std::string_view("_"), 2u) == 2u);
                    CHECK(j.value(std::string_view("_"), false) == false);
                    CHECK(j.value(std::string_view("_"), "bar") == "bar");
                    CHECK(j.value(std::string_view("_"), 12.34) == Approx(12.34));
                    CHECK(j.value(std::string_view("_"), Json({{"foo", "bar"}})) == Json({{"foo", "bar"}}));
                    CHECK(j.value(std::string_view("_"), Json({10, 100})) == Json({10, 100}));

                    CHECK(j_const.value(std::string_view("_"), 2) == 2);
                    CHECK(j_const.value(std::string_view("_"), 2u) == 2u);
                    CHECK(j_const.value(std::string_view("_"), false) == false);
                    CHECK(j_const.value(std::string_view("_"), "bar") == "bar");
                    CHECK(j_const.value(std::string_view("_"), 12.34) == Approx(12.34));
                    CHECK(j_const.value(std::string_view("_"), Json({{"foo", "bar"}})) == Json({{"foo", "bar"}}));
                    CHECK(j_const.value(std::string_view("_"), Json({10, 100})) == Json({10, 100}));
                }

                SECTION("access on non-object type")
                {
                    SECTION("null")
                    {
                        Json j_nonobject(Json::value_t::null);
                        const Json j_nonobject_const(Json::value_t::null);

                        CHECK_THROWS_WITH_AS(j_nonobject.value(std::string_view("foo"), 1), "[json.exception.type_error.306] cannot use value() with null", typename Json::type_error&);
                        CHECK_THROWS_WITH_AS(j_nonobject_const.value(std::string_view("foo"), 1), "[json.exception.type_error.306] cannot use value() with null", typename Json::type_error&);
                    }

                    SECTION("boolean")
                    {
                        Json j_nonobject(Json::value_t::boolean);
                        const Json j_nonobject_const(Json::value_t::boolean);

                        CHECK_THROWS_WITH_AS(j_nonobject.value(std::string_view("foo"), 1), "[json.exception.type_error.306] cannot use value() with boolean", typename Json::type_error&);
                        CHECK_THROWS_WITH_AS(j_nonobject_const.value(std::string_view("foo"), 1), "[json.exception.type_error.306] cannot use value() with boolean", typename Json::type_error&);
                    }

                    SECTION("string")
                    {
                        Json j_nonobject(Json::value_t::string);
                        const Json j_nonobject_const(Json::value_t::string);

                        CHECK_THROWS_WITH_AS(j_nonobject.value(std::string_view("foo"), 1), "[json.exception.type_error.306] cannot use value() with string", typename Json::type_error&);
                        CHECK_THROWS_WITH_AS(j_nonobject_const.value(std::string_view("foo"), 1), "[json.exception.type_error.306] cannot use value() with string", typename Json::type_error&);
                    }

                    SECTION("array")
                    {
                        Json j_nonobject(Json::value_t::array);
                        const Json j_nonobject_const(Json::value_t::array);

                        CHECK_THROWS_WITH_AS(j_nonobject.value(std::string_view("foo"), 1), "[json.exception.type_error.306] cannot use value() with array", typename Json::type_error&);
                        CHECK_THROWS_WITH_AS(j_nonobject_const.value(std::string_view("foo"), 1), "[json.exception.type_error.306] cannot use value() with array", typename Json::type_error&);
                    }

                    SECTION("number (integer)")
                    {
                        Json j_nonobject(Json::value_t::number_integer);
                        const Json j_nonobject_const(Json::value_t::number_integer);

                        CHECK_THROWS_WITH_AS(j_nonobject.value(std::string_view("foo"), 1), "[json.exception.type_error.306] cannot use value() with number", typename Json::type_error&);
                        CHECK_THROWS_WITH_AS(j_nonobject_const.value(std::string_view("foo"), 1), "[json.exception.type_error.306] cannot use value() with number", typename Json::type_error&);
                    }

                    SECTION("number (unsigned)")
                    {
                        Json j_nonobject(Json::value_t::number_unsigned);
                        const Json j_nonobject_const(Json::value_t::number_unsigned);

                        CHECK_THROWS_WITH_AS(j_nonobject.value(std::string_view("foo"), 1), "[json.exception.type_error.306] cannot use value() with number", typename Json::type_error&);
                        CHECK_THROWS_WITH_AS(j_nonobject_const.value(std::string_view("foo"), 1), "[json.exception.type_error.306] cannot use value() with number", typename Json::type_error&);
                    }

                    SECTION("number (floating-point)")
                    {
                        Json j_nonobject(Json::value_t::number_float);
                        const Json j_nonobject_const(Json::value_t::number_float);

                        CHECK_THROWS_WITH_AS(j_nonobject.value(std::string_view("foo"), 1), "[json.exception.type_error.306] cannot use value() with number", typename Json::type_error&);
                        CHECK_THROWS_WITH_AS(j_nonobject_const.value(std::string_view("foo"), 1), "[json.exception.type_error.306] cannot use value() with number", typename Json::type_error&);
                    }
                }
            }
        }

        SECTION("non-const operator[]")
        {
            {
                std::string_view const key = "key";
                Json j_null;
                CHECK(j_null.is_null());
                j_null[key] = 1;
                CHECK(j_null.is_object());
                CHECK(j_null.size() == 1);
                j_null[key] = 2;
                CHECK(j_null.size() == 1);
            }
        }

        SECTION("access specified element")
        {
            SECTION("access within bounds (string_view)")
            {
                CHECK(j["integer"] == Json(1));
                CHECK(j[std::string_view("integer")] == j["integer"]);

                CHECK(j["unsigned"] == Json(1u));
                CHECK(j[std::string_view("unsigned")] == j["unsigned"]);

                CHECK(j["boolean"] == Json(true));
                CHECK(j[std::string_view("boolean")] == j["boolean"]);

                CHECK(j["null"] == Json(nullptr));
                CHECK(j[std::string_view("null")] == j["null"]);

                CHECK(j["string"] == Json("hello world"));
                CHECK(j[std::string_view("string")] == j["string"]);

                CHECK(j["floating"] == Json(42.23));
                CHECK(j[std::string_view("floating")] == j["floating"]);

                CHECK(j["object"] == Json::object());
                CHECK(j[std::string_view("object")] == j["object"]);

                CHECK(j["array"] == Json({1, 2, 3}));
                CHECK(j[std::string_view("array")] == j["array"]);

                CHECK(j_const["integer"] == Json(1));
                CHECK(j_const[std::string_view("integer")] == j["integer"]);

                CHECK(j_const["boolean"] == Json(true));
                CHECK(j_const[std::string_view("boolean")] == j["boolean"]);

                CHECK(j_const["null"] == Json(nullptr));
                CHECK(j_const[std::string_view("null")] == j["null"]);

                CHECK(j_const["string"] == Json("hello world"));
                CHECK(j_const[std::string_view("string")] == j["string"]);

                CHECK(j_const["floating"] == Json(42.23));
                CHECK(j_const[std::string_view("floating")] == j["floating"]);

                CHECK(j_const["object"] == Json::object());
                CHECK(j_const[std::string_view("object")] == j["object"]);

                CHECK(j_const["array"] == Json({1, 2, 3}));
                CHECK(j_const[std::string_view("array")] == j["array"]);
            }

            SECTION("access on non-object type")
            {
                SECTION("null")
                {
                    Json j_nonobject(Json::value_t::null);
                    Json j_nonobject2(Json::value_t::null);
                    const Json j_const_nonobject(j_nonobject);

                    CHECK_NOTHROW(j_nonobject2[std::string_view("foo")]);
                    CHECK_THROWS_WITH_AS(j_const_nonobject[std::string_view("foo")], "[json.exception.type_error.305] cannot use operator[] with a string argument with null", typename Json::type_error&);
                }

                SECTION("boolean")
                {
                    Json j_nonobject(Json::value_t::boolean);
                    const Json j_const_nonobject(j_nonobject);

                    CHECK_THROWS_WITH_AS(j_nonobject[std::string_view("foo")], "[json.exception.type_error.305] cannot use operator[] with a string argument with boolean", typename Json::type_error&);
                    CHECK_THROWS_WITH_AS(j_const_nonobject[std::string_view("foo")], "[json.exception.type_error.305] cannot use operator[] with a string argument with boolean", typename Json::type_error&);
                }

                SECTION("string")
                {
                    Json j_nonobject(Json::value_t::string);
                    const Json j_const_nonobject(j_nonobject);

                    CHECK_THROWS_WITH_AS(j_nonobject[std::string_view("foo")], "[json.exception.type_error.305] cannot use operator[] with a string argument with string", typename Json::type_error&);
                    CHECK_THROWS_WITH_AS(j_const_nonobject[std::string_view("foo")], "[json.exception.type_error.305] cannot use operator[] with a string argument with string", typename Json::type_error&);
                }

                SECTION("array")
                {
                    Json j_nonobject(Json::value_t::array);
                    const Json j_const_nonobject(j_nonobject);

                    CHECK_THROWS_WITH_AS(j_nonobject[std::string_view("foo")], "[json.exception.type_error.305] cannot use operator[] with a string argument with array", typename Json::type_error&);
                    CHECK_THROWS_WITH_AS(j_const_nonobject[std::string_view("foo")], "[json.exception.type_error.305] cannot use operator[] with a string argument with array", typename Json::type_error&);
                }

                SECTION("number (integer)")
                {
                    Json j_nonobject(Json::value_t::number_integer);
                    const Json j_const_nonobject(j_nonobject);

                    CHECK_THROWS_WITH_AS(j_nonobject[std::string_view("foo")], "[json.exception.type_error.305] cannot use operator[] with a string argument with number", typename Json::type_error&);
                    CHECK_THROWS_WITH_AS(j_const_nonobject[std::string_view("foo")], "[json.exception.type_error.305] cannot use operator[] with a string argument with number", typename Json::type_error&);
                }

                SECTION("number (unsigned)")
                {
                    Json j_nonobject(Json::value_t::number_unsigned);
                    const Json j_const_nonobject(j_nonobject);

                    CHECK_THROWS_WITH_AS(j_nonobject[std::string_view("foo")], "[json.exception.type_error.305] cannot use operator[] with a string argument with number", typename Json::type_error&);
                    CHECK_THROWS_WITH_AS(j_const_nonobject[std::string_view("foo")], "[json.exception.type_error.305] cannot use operator[] with a string argument with number", typename Json::type_error&);
                }

                SECTION("number (floating-point)")
                {
                    Json j_nonobject(Json::value_t::number_float);
                    const Json j_const_nonobject(j_nonobject);

                    CHECK_THROWS_WITH_AS(j_nonobject[std::string_view("foo")], "[json.exception.type_error.305] cannot use operator[] with a string argument with number", typename Json::type_error&);
                    CHECK_THROWS_WITH_AS(j_const_nonobject[std::string_view("foo")], "[json.exception.type_error.305] cannot use operator[] with a string argument with number", typename Json::type_error&);
                }
            }
        }

        SECTION("remove specified element")
        {
            SECTION("remove element by key (string_view)")
            {
                CHECK(j.find(std::string_view("integer")) != j.end());
                CHECK(j.erase(std::string_view("integer")) == 1);
                CHECK(j.find(std::string_view("integer")) == j.end());
                CHECK(j.erase(std::string_view("integer")) == 0);

                CHECK(j.find(std::string_view("unsigned")) != j.end());
                CHECK(j.erase(std::string_view("unsigned")) == 1);
                CHECK(j.find(std::string_view("unsigned")) == j.end());
                CHECK(j.erase(std::string_view("unsigned")) == 0);

                CHECK(j.find(std::string_view("boolean")) != j.end());
                CHECK(j.erase(std::string_view("boolean")) == 1);
                CHECK(j.find(std::string_view("boolean")) == j.end());
                CHECK(j.erase(std::string_view("boolean")) == 0);

                CHECK(j.find(std::string_view("null")) != j.end());
                CHECK(j.erase(std::string_view("null")) == 1);
                CHECK(j.find(std::string_view("null")) == j.end());
                CHECK(j.erase(std::string_view("null")) == 0);

                CHECK(j.find(std::string_view("string")) != j.end());
                CHECK(j.erase(std::string_view("string")) == 1);
                CHECK(j.find(std::string_view("string")) == j.end());
                CHECK(j.erase(std::string_view("string")) == 0);

                CHECK(j.find(std::string_view("floating")) != j.end());
                CHECK(j.erase(std::string_view("floating")) == 1);
                CHECK(j.find(std::string_view("floating")) == j.end());
                CHECK(j.erase(std::string_view("floating")) == 0);

                CHECK(j.find(std::string_view("object")) != j.end());
                CHECK(j.erase(std::string_view("object")) == 1);
                CHECK(j.find(std::string_view("object")) == j.end());
                CHECK(j.erase(std::string_view("object")) == 0);

                CHECK(j.find(std::string_view("array")) != j.end());
                CHECK(j.erase(std::string_view("array")) == 1);
                CHECK(j.find(std::string_view("array")) == j.end());
                CHECK(j.erase(std::string_view("array")) == 0);
            }

            SECTION("remove element by key in non-object type")
            {
                SECTION("null")
                {
                    Json j_nonobject(Json::value_t::null);

                    CHECK_THROWS_WITH_AS(j_nonobject.erase(std::string_view("foo")), "[json.exception.type_error.307] cannot use erase() with null", typename Json::type_error&);
                }

                SECTION("boolean")
                {
                    Json j_nonobject(Json::value_t::boolean);

                    CHECK_THROWS_WITH_AS(j_nonobject.erase(std::string_view("foo")), "[json.exception.type_error.307] cannot use erase() with boolean", typename Json::type_error&);
                }

                SECTION("string")
                {
                    Json j_nonobject(Json::value_t::string);

                    CHECK_THROWS_WITH_AS(j_nonobject.erase(std::string_view("foo")), "[json.exception.type_error.307] cannot use erase() with string", typename Json::type_error&);
                }

                SECTION("array")
                {
                    Json j_nonobject(Json::value_t::array);

                    CHECK_THROWS_WITH_AS(j_nonobject.erase(std::string_view("foo")), "[json.exception.type_error.307] cannot use erase() with array", typename Json::type_error&);
                }

                SECTION("number (integer)")
                {
                    Json j_nonobject(Json::value_t::number_integer);

                    CHECK_THROWS_WITH_AS(j_nonobject.erase(std::string_view("foo")), "[json.exception.type_error.307] cannot use erase() with number", typename Json::type_error&);
                }

                SECTION("number (floating-point)")
                {
                    Json j_nonobject(Json::value_t::number_float);

                    CHECK_THROWS_WITH_AS(j_nonobject.erase(std::string_view("foo")), "[json.exception.type_error.307] cannot use erase() with number", typename Json::type_error&);
                }
            }
        }

        SECTION("find an element in an object")
        {
            SECTION("existing element")
            {
                for (const std::string_view key :
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
                CHECK(j.find(std::string_view("foo")) == j.end());
                CHECK(j_const.find(std::string_view("foo")) == j_const.end());
            }

            SECTION("all types")
            {
                SECTION("null")
                {
                    Json j_nonarray(Json::value_t::null);
                    const Json j_nonarray_const(j_nonarray);

                    CHECK(j_nonarray.find(std::string_view("foo")) == j_nonarray.end());
                    CHECK(j_nonarray_const.find(std::string_view("foo")) == j_nonarray_const.end());
                }

                SECTION("string")
                {
                    Json j_nonarray(Json::value_t::string);
                    const Json j_nonarray_const(j_nonarray);

                    CHECK(j_nonarray.find(std::string_view("foo")) == j_nonarray.end());
                    CHECK(j_nonarray_const.find(std::string_view("foo")) == j_nonarray_const.end());
                }

                SECTION("object")
                {
                    Json j_nonarray(Json::value_t::object);
                    const Json j_nonarray_const(j_nonarray);

                    CHECK(j_nonarray.find(std::string_view("foo")) == j_nonarray.end());
                    CHECK(j_nonarray_const.find(std::string_view("foo")) == j_nonarray_const.end());
                }

                SECTION("array")
                {
                    Json j_nonarray(Json::value_t::array);
                    const Json j_nonarray_const(j_nonarray);

                    CHECK(j_nonarray.find(std::string_view("foo")) == j_nonarray.end());
                    CHECK(j_nonarray_const.find(std::string_view("foo")) == j_nonarray_const.end());
                }

                SECTION("boolean")
                {
                    Json j_nonarray(Json::value_t::boolean);
                    const Json j_nonarray_const(j_nonarray);

                    CHECK(j_nonarray.find(std::string_view("foo")) == j_nonarray.end());
                    CHECK(j_nonarray_const.find(std::string_view("foo")) == j_nonarray_const.end());
                }

                SECTION("number (integer)")
                {
                    Json j_nonarray(Json::value_t::number_integer);
                    const Json j_nonarray_const(j_nonarray);

                    CHECK(j_nonarray.find(std::string_view("foo")) == j_nonarray.end());
                    CHECK(j_nonarray_const.find(std::string_view("foo")) == j_nonarray_const.end());
                }

                SECTION("number (unsigned)")
                {
                    Json j_nonarray(Json::value_t::number_unsigned);
                    const Json j_nonarray_const(j_nonarray);

                    CHECK(j_nonarray.find(std::string_view("foo")) == j_nonarray.end());
                    CHECK(j_nonarray_const.find(std::string_view("foo")) == j_nonarray_const.end());
                }

                SECTION("number (floating-point)")
                {
                    Json j_nonarray(Json::value_t::number_float);
                    const Json j_nonarray_const(j_nonarray);

                    CHECK(j_nonarray.find(std::string_view("foo")) == j_nonarray.end());
                    CHECK(j_nonarray_const.find(std::string_view("foo")) == j_nonarray_const.end());
                }
            }
        }

        SECTION("count keys in an object")
        {
            SECTION("existing element")
            {
                for (const std::string_view key :
                        {"integer", "unsigned", "floating", "null", "string", "boolean", "object", "array"
                        })
                {
                    CHECK(j.count(key) == 1);
                    CHECK(j_const.count(key) == 1);
                }
            }

            SECTION("nonexisting element")
            {
                CHECK(j.count(std::string_view("foo")) == 0);
                CHECK(j_const.count(std::string_view("foo")) == 0);
            }

            SECTION("all types")
            {
                SECTION("null")
                {
                    Json j_nonobject(Json::value_t::null);
                    const Json j_nonobject_const(Json::value_t::null);

                    CHECK(j.count(std::string_view("foo")) == 0);
                    CHECK(j_const.count(std::string_view("foo")) == 0);
                }

                SECTION("string")
                {
                    Json j_nonobject(Json::value_t::string);
                    const Json j_nonobject_const(Json::value_t::string);

                    CHECK(j.count(std::string_view("foo")) == 0);
                    CHECK(j_const.count(std::string_view("foo")) == 0);
                }

                SECTION("object")
                {
                    Json j_nonobject(Json::value_t::object);
                    const Json j_nonobject_const(Json::value_t::object);

                    CHECK(j.count(std::string_view("foo")) == 0);
                    CHECK(j_const.count(std::string_view("foo")) == 0);
                }

                SECTION("array")
                {
                    Json j_nonobject(Json::value_t::array);
                    const Json j_nonobject_const(Json::value_t::array);

                    CHECK(j.count(std::string_view("foo")) == 0);
                    CHECK(j_const.count(std::string_view("foo")) == 0);
                }

                SECTION("boolean")
                {
                    Json j_nonobject(Json::value_t::boolean);
                    const Json j_nonobject_const(Json::value_t::boolean);

                    CHECK(j.count(std::string_view("foo")) == 0);
                    CHECK(j_const.count(std::string_view("foo")) == 0);
                }

                SECTION("number (integer)")
                {
                    Json j_nonobject(Json::value_t::number_integer);
                    const Json j_nonobject_const(Json::value_t::number_integer);

                    CHECK(j.count(std::string_view("foo")) == 0);
                    CHECK(j_const.count(std::string_view("foo")) == 0);
                }

                SECTION("number (unsigned)")
                {
                    Json j_nonobject(Json::value_t::number_unsigned);
                    const Json j_nonobject_const(Json::value_t::number_unsigned);

                    CHECK(j.count(std::string_view("foo")) == 0);
                    CHECK(j_const.count(std::string_view("foo")) == 0);
                }

                SECTION("number (floating-point)")
                {
                    Json j_nonobject(Json::value_t::number_float);
                    const Json j_nonobject_const(Json::value_t::number_float);

                    CHECK(j.count(std::string_view("foo")) == 0);
                    CHECK(j_const.count(std::string_view("foo")) == 0);
                }
            }
        }

        SECTION("check existence of key in an object")
        {
            SECTION("existing element")
            {
                for (const std::string_view key :
                        {"integer", "unsigned", "floating", "null", "string", "boolean", "object", "array"
                        })
                {
                    CHECK(j.contains(key) == true);
                    CHECK(j_const.contains(key) == true);
                }
            }

            SECTION("nonexisting element")
            {
                CHECK(j.contains(std::string_view("foo")) == false);
                CHECK(j_const.contains(std::string_view("foo")) == false);
            }

            SECTION("all types")
            {
                SECTION("null")
                {
                    Json j_nonobject(Json::value_t::null);
                    const Json j_nonobject_const(Json::value_t::null);

                    CHECK(j_nonobject.contains(std::string_view("foo")) == false);
                    CHECK(j_nonobject_const.contains(std::string_view("foo")) == false);
                }

                SECTION("string")
                {
                    Json j_nonobject(Json::value_t::string);
                    const Json j_nonobject_const(Json::value_t::string);

                    CHECK(j_nonobject.contains(std::string_view("foo")) == false);
                    CHECK(j_nonobject_const.contains(std::string_view("foo")) == false);
                }

                SECTION("object")
                {
                    Json j_nonobject(Json::value_t::object);
                    const Json j_nonobject_const(Json::value_t::object);

                    CHECK(j_nonobject.contains(std::string_view("foo")) == false);
                    CHECK(j_nonobject_const.contains(std::string_view("foo")) == false);
                }

                SECTION("array")
                {
                    Json j_nonobject(Json::value_t::array);
                    const Json j_nonobject_const(Json::value_t::array);

                    CHECK(j_nonobject.contains(std::string_view("foo")) == false);
                    CHECK(j_nonobject_const.contains(std::string_view("foo")) == false);
                }

                SECTION("boolean")
                {
                    Json j_nonobject(Json::value_t::boolean);
                    const Json j_nonobject_const(Json::value_t::boolean);

                    CHECK(j_nonobject.contains(std::string_view("foo")) == false);
                    CHECK(j_nonobject_const.contains(std::string_view("foo")) == false);
                }

                SECTION("number (integer)")
                {
                    Json j_nonobject(Json::value_t::number_integer);
                    const Json j_nonobject_const(Json::value_t::number_integer);

                    CHECK(j_nonobject.contains(std::string_view("foo")) == false);
                    CHECK(j_nonobject_const.contains(std::string_view("foo")) == false);
                }

                SECTION("number (unsigned)")
                {
                    Json j_nonobject(Json::value_t::number_unsigned);
                    const Json j_nonobject_const(Json::value_t::number_unsigned);

                    CHECK(j_nonobject.contains(std::string_view("foo")) == false);
                    CHECK(j_nonobject_const.contains(std::string_view("foo")) == false);
                }

                SECTION("number (floating-point)")
                {
                    Json j_nonobject(Json::value_t::number_float);
                    const Json j_nonobject_const(Json::value_t::number_float);
                    CHECK(j_nonobject.contains(std::string_view("foo")) == false);
                    CHECK(j_nonobject_const.contains(std::string_view("foo")) == false);
                }
            }
        }
    }

    SECTION("integral keys for object lookup are rejected at compile time")
    {
        // https://github.com/nlohmann/json/issues/5657: an integer literal like 0 is a null pointer
        // constant, which used to convert to a null const char* and from there--via undefined
        // behavior in the std::string constructor--to key_type, so contains(0), find(0), and
        // count(0) used to compile and then crash instead of failing to compile
        using nlohmann::detail::is_detected;

        CHECK(is_detected<can_call_sv_find, Json&, std::string_view>::value);
        CHECK(is_detected<can_call_sv_count, Json&, std::string_view>::value);
        CHECK(is_detected<can_call_sv_contains, Json&, std::string_view>::value);

        // the neighboring size_type overloads for array access are unaffected by the new
        // integral-key overloads above (at(), operator[](), and erase() take a size_type)
        Json arr = {10, 20, 30};
        const Json arr_const = arr;
        arr.erase(0);
    }
}

TEST_CASE_TEMPLATE("element access 2 (additional value() tests) (C++17)", Json, nlohmann::json, nlohmann::ordered_json) // NOLINT(readability-math-missing-parentheses, bugprone-throwing-static-initialization)
{
    using string_t = typename Json::string_t;
    using number_integer_t = typename Json::number_integer_t;

    // test assumes string_t and object_t::key_type are the same
    REQUIRE(std::is_same<string_t, typename Json::object_t::key_type>::value);

    Json j
    {
        {"foo", "bar"},
        {"baz", 42}
    };

    const char* cpstr = "default";
    const char castr[] = "default"; // NOLINT(hicpp-avoid-c-arrays,modernize-avoid-c-arrays,cppcoreguidelines-avoid-c-arrays)
    string_t const str = "default";

    number_integer_t integer = 69;
    std::size_t size = 69;

    SECTION("deduced ValueType")
    {
        SECTION("std::string_view key")
        {
            std::string_view const key = "foo";
            std::string_view const key2 = "baz";
            std::string_view const key_notfound = "bar";

            CHECK(j.value(key, "default") == "bar");
            CHECK(j.value(key, cpstr) == "bar");
            CHECK(j.value(key, castr) == "bar");
            CHECK(j.value(key, str) == "bar");
            CHECK(j.value(key2, 0) == 42);
            CHECK(j.value(key2, 47) == 42);
            CHECK(j.value(key2, integer) == 42);
            CHECK(j.value(key2, size) == 42);

            CHECK(j.value(key_notfound, "default") == "default");
            CHECK(j.value(key_notfound, 0) == 0);
            CHECK(j.value(key_notfound, 47) == 47);
            CHECK(j.value(key_notfound, integer) == integer);
            CHECK(j.value(key_notfound, size) == size);

            CHECK_THROWS_WITH_AS(Json().value(key, "default"), "[json.exception.type_error.306] cannot use value() with null", typename Json::type_error&);
            CHECK_THROWS_WITH_AS(Json().value(key, str), "[json.exception.type_error.306] cannot use value() with null", typename Json::type_error&);
        }
    }

    SECTION("explicit ValueType")
    {
        SECTION("std::string_view key")
        {
            std::string_view const key = "foo";
            std::string_view const key2 = "baz";
            std::string_view const key_notfound = "bar";

            CHECK(j.template value<string_t>(key, "default") == "bar");
            CHECK(j.template value<string_t>(key, cpstr) == "bar");
            CHECK(j.template value<string_t>(key, castr) == "bar");
            CHECK(j.template value<string_t>(key, str) == "bar");
            CHECK(j.template value<number_integer_t>(key2, 0) == 42);
            CHECK(j.template value<number_integer_t>(key2, 47) == 42);
            CHECK(j.template value<number_integer_t>(key2, integer) == 42);
            CHECK(j.template value<std::size_t>(key2, 0) == 42);
            CHECK(j.template value<std::size_t>(key2, 47) == 42);
            CHECK(j.template value<std::size_t>(key2, size) == 42);

            CHECK(j.template value<string_t>(key_notfound, "default") == "default");
            CHECK(j.template value<number_integer_t>(key_notfound, 0) == 0);
            CHECK(j.template value<number_integer_t>(key_notfound, 47) == 47);
            CHECK(j.template value<number_integer_t>(key_notfound, integer) == integer);
            CHECK(j.template value<std::size_t>(key_notfound, 0) == 0);
            CHECK(j.template value<std::size_t>(key_notfound, 47) == 47);
            CHECK(j.template value<std::size_t>(key_notfound, size) == size);

            CHECK(j.template value<std::string_view>(key, "default") == "bar");
            CHECK(j.template value<std::string_view>(key, cpstr) == "bar");
            CHECK(j.template value<std::string_view>(key, castr) == "bar");
            CHECK(j.template value<std::string_view>(key, str) == "bar");

            CHECK(j.template value<std::string_view>(key_notfound, "default") == "default");

            CHECK_THROWS_WITH_AS(Json().template value<string_t>(key, "default"), "[json.exception.type_error.306] cannot use value() with null", typename Json::type_error&);
            CHECK_THROWS_WITH_AS(Json().template value<string_t>(key, str), "[json.exception.type_error.306] cannot use value() with null", typename Json::type_error&);
        }
    }
}

TEST_CASE("operator[] with user-defined std::string_view-convertible types")
{
    using json = nlohmann::json;

    class TestClass
    {
        std::string key_data_ = "foo";

      public:
        operator std::string_view() const
        {
            return key_data_;
        }
    };

    struct TestStruct
    {
        operator std::string_view() const
        {
            return "bar";
        }
    };

    json j = {{"foo", "from_class"}, {"bar", "from_struct"}};
    const TestClass foo_obj;
    const TestStruct bar_obj;

    SECTION("read access")
    {
        CHECK(j[foo_obj] == "from_class");
        CHECK(j[TestClass{}] == "from_class");
        CHECK(j[bar_obj] == "from_struct");
        CHECK(j[TestStruct{}] == "from_struct");
    }

    SECTION("write access")
    {
        j[TestClass{}] = "updated_class";
        j[TestStruct{}] = "updated_struct";
        CHECK(j["foo"] == "updated_class");
        CHECK(j["bar"] == "updated_struct");

        SECTION("direct std::string_view access")
        {
            CHECK(j[std::string_view{"foo"}] == "updated_class");
            CHECK(j[std::string_view{"bar"}] == "updated_struct");
        }
    }
}

TEST_CASE("keys convertible to std::string_view work with all lookup functions (regression test for #5663)")
{
    // a key type convertible only to std::string_view: the case #4958 added
    // support for, but only the non-const operator[] compiled with it
    struct ViewKey
    {
        operator std::string_view() const
        {
            return "a";
        }
    };

    // a key type convertible to both std::string and std::string_view: with
    // 3.12.0, such a key worked with at, the const operator[], find, count and
    // contains via the conversion to std::string; #4958 made the KeyType&&
    // templates win overload resolution for it instead, and those then failed
    // the lookups pick the conversion to std::string_view, which leaves the one
    // to std::string unused; it has to exist to reproduce the ambiguity
    DOCTEST_CLANG_SUPPRESS_WARNING_PUSH
    DOCTEST_CLANG_SUPPRESS_WARNING("-Wunused-member-function")
    struct DualKey
    {
        operator std::string() const
        {
            return "a";
        }
        operator std::string_view() const
        {
            return "a";
        }
    };
    DOCTEST_CLANG_SUPPRESS_WARNING_POP

    SECTION("nlohmann::json")
    {
        using json = nlohmann::json;

        SECTION("ViewKey")
        {
            json j = {{"a", 1}};
            const json& cj = j;

            CHECK(j[ViewKey{}] == 1);
            CHECK(cj[ViewKey{}] == 1);
            CHECK(j.at(ViewKey{}) == 1);
            CHECK(cj.at(ViewKey{}) == 1);
            CHECK(j.find(ViewKey{}) != j.end());
            CHECK(cj.find(ViewKey{}) != cj.end());
            CHECK(j.count(ViewKey{}) == 1);
            CHECK(j.contains(ViewKey{}));
            CHECK(j.value(ViewKey{}, 0) == 1);
            CHECK(j.erase(ViewKey{}) == 1);
            CHECK(!j.contains("a"));
        }

        SECTION("DualKey")
        {
            json j = {{"a", 1}};
            const json& cj = j;

            CHECK(j[DualKey{}] == 1);
            CHECK(cj[DualKey{}] == 1);
            CHECK(j.at(DualKey{}) == 1);
            CHECK(cj.at(DualKey{}) == 1);
            CHECK(j.find(DualKey{}) != j.end());
            CHECK(cj.find(DualKey{}) != cj.end());
            CHECK(j.count(DualKey{}) == 1);
            CHECK(j.contains(DualKey{}));
            CHECK(j.value(DualKey{}, 0) == 1);
            CHECK(j.erase(DualKey{}) == 1);
            CHECK(!j.contains("a"));
        }
    }

    SECTION("nlohmann::ordered_json")
    {
        using ordered_json = nlohmann::ordered_json;

        SECTION("ViewKey")
        {
            ordered_json j = {{"a", 1}};
            const ordered_json& cj = j;

            CHECK(j[ViewKey{}] == 1);
            CHECK(cj[ViewKey{}] == 1);
            CHECK(j.at(ViewKey{}) == 1);
            CHECK(cj.at(ViewKey{}) == 1);
            CHECK(j.find(ViewKey{}) != j.end());
            CHECK(cj.find(ViewKey{}) != cj.end());
            CHECK(j.count(ViewKey{}) == 1);
            CHECK(j.contains(ViewKey{}));
            CHECK(j.value(ViewKey{}, 0) == 1);
            CHECK(j.erase(ViewKey{}) == 1);
            CHECK(!j.contains("a"));
        }

        SECTION("DualKey")
        {
            ordered_json j = {{"a", 1}};
            const ordered_json& cj = j;

            CHECK(j[DualKey{}] == 1);
            CHECK(cj[DualKey{}] == 1);
            CHECK(j.at(DualKey{}) == 1);
            CHECK(cj.at(DualKey{}) == 1);
            CHECK(j.find(DualKey{}) != j.end());
            CHECK(cj.find(DualKey{}) != cj.end());
            CHECK(j.count(DualKey{}) == 1);
            CHECK(j.contains(DualKey{}));
            CHECK(j.value(DualKey{}, 0) == 1);
            CHECK(j.erase(DualKey{}) == 1);
            CHECK(!j.contains("a"));
        }
    }
}

#endif
