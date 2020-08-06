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
DOCTEST_GCC_SUPPRESS_WARNING("-Wfloat-equal")

#include <nlohmann/json.hpp>
using nlohmann::json;

TEST_CASE("reference access")
{
    // create a JSON value with different types
    json json_types =
    {
        {"boolean", true},
        {
            "number", {
                {"integer", 42},
                {"floating-point", 17.23}
            }
        },
        {"string", "Hello, world!"},
        {"array", {1, 2, 3, 4, 5}},
        {"null", nullptr}
    };

    SECTION("reference access to object_t")
    {
        using test_type = json::object_t;
        json value = {{"one", 1}, {"two", 2}};

        // check if references are returned correctly
        test_type& p1 = value.get_ref<test_type&>();
        CHECK(&p1 == value.get_ptr<test_type*>());
        CHECK(p1 == value.get<test_type>());

        const test_type& p2 = value.get_ref<const test_type&>();
        CHECK(&p2 == value.get_ptr<const test_type*>());
        CHECK(p2 == value.get<test_type>());

        // check if mismatching references throw correctly
        CHECK_NOTHROW(value.get_ref<json::object_t&>());
        CHECK_THROWS_AS(value.get_ref<json::array_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::array_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is object");
        CHECK_THROWS_AS(value.get_ref<json::string_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::string_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is object");
        CHECK_THROWS_AS(value.get_ref<json::boolean_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::boolean_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is object");
        CHECK_THROWS_AS(value.get_ref<json::number_integer_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::number_integer_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is object");
        CHECK_THROWS_AS(value.get_ref<json::number_unsigned_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::number_unsigned_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is object");
        CHECK_THROWS_AS(value.get_ref<json::number_float_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::number_float_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is object");
    }

    SECTION("const reference access to const object_t")
    {
        using test_type = json::object_t;
        const json value = {{"one", 1}, {"two", 2}};

        // this should not compile
        // test_type& p1 = value.get_ref<test_type&>();

        // check if references are returned correctly
        const test_type& p2 = value.get_ref<const test_type&>();
        CHECK(&p2 == value.get_ptr<const test_type*>());
        CHECK(p2 == value.get<test_type>());
    }

    SECTION("reference access to array_t")
    {
        using test_type = json::array_t;
        json value = {1, 2, 3, 4};

        // check if references are returned correctly
        test_type& p1 = value.get_ref<test_type&>();
        CHECK(&p1 == value.get_ptr<test_type*>());
        CHECK(p1 == value.get<test_type>());

        const test_type& p2 = value.get_ref<const test_type&>();
        CHECK(&p2 == value.get_ptr<const test_type*>());
        CHECK(p2 == value.get<test_type>());

        // check if mismatching references throw correctly
        CHECK_THROWS_AS(value.get_ref<json::object_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::object_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is array");
        CHECK_NOTHROW(value.get_ref<json::array_t&>());
        CHECK_THROWS_AS(value.get_ref<json::string_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::string_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is array");
        CHECK_THROWS_AS(value.get_ref<json::boolean_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::boolean_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is array");
        CHECK_THROWS_AS(value.get_ref<json::number_integer_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::number_integer_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is array");
        CHECK_THROWS_AS(value.get_ref<json::number_unsigned_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::number_unsigned_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is array");
        CHECK_THROWS_AS(value.get_ref<json::number_float_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::number_float_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is array");
    }

    SECTION("reference access to string_t")
    {
        using test_type = json::string_t;
        json value = "hello";

        // check if references are returned correctly
        test_type& p1 = value.get_ref<test_type&>();
        CHECK(&p1 == value.get_ptr<test_type*>());
        CHECK(p1 == value.get<test_type>());

        const test_type& p2 = value.get_ref<const test_type&>();
        CHECK(&p2 == value.get_ptr<const test_type*>());
        CHECK(p2 == value.get<test_type>());

        // check if mismatching references throw correctly
        CHECK_THROWS_AS(value.get_ref<json::object_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::object_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is string");
        CHECK_THROWS_AS(value.get_ref<json::array_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::array_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is string");
        CHECK_NOTHROW(value.get_ref<json::string_t&>());
        CHECK_THROWS_AS(value.get_ref<json::boolean_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::boolean_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is string");
        CHECK_THROWS_AS(value.get_ref<json::number_integer_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::number_integer_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is string");
        CHECK_THROWS_AS(value.get_ref<json::number_unsigned_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::number_unsigned_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is string");
        CHECK_THROWS_AS(value.get_ref<json::number_float_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::number_float_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is string");
    }

    SECTION("reference access to boolean_t")
    {
        using test_type = json::boolean_t;
        json value = false;

        // check if references are returned correctly
        test_type& p1 = value.get_ref<test_type&>();
        CHECK(&p1 == value.get_ptr<test_type*>());
        CHECK(p1 == value.get<test_type>());

        const test_type& p2 = value.get_ref<const test_type&>();
        CHECK(&p2 == value.get_ptr<const test_type*>());
        CHECK(p2 == value.get<test_type>());

        // check if mismatching references throw correctly
        CHECK_THROWS_AS(value.get_ref<json::object_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::object_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is boolean");
        CHECK_THROWS_AS(value.get_ref<json::array_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::array_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is boolean");
        CHECK_THROWS_AS(value.get_ref<json::string_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::string_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is boolean");
        CHECK_NOTHROW(value.get_ref<json::boolean_t&>());
        CHECK_THROWS_AS(value.get_ref<json::number_integer_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::number_integer_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is boolean");
        CHECK_THROWS_AS(value.get_ref<json::number_unsigned_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::number_unsigned_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is boolean");
        CHECK_THROWS_AS(value.get_ref<json::number_float_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::number_float_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is boolean");
    }

    SECTION("reference access to number_integer_t")
    {
        using test_type = json::number_integer_t;
        json value = -23;

        // check if references are returned correctly
        test_type& p1 = value.get_ref<test_type&>();
        CHECK(&p1 == value.get_ptr<test_type*>());
        CHECK(p1 == value.get<test_type>());

        const test_type& p2 = value.get_ref<const test_type&>();
        CHECK(&p2 == value.get_ptr<const test_type*>());
        CHECK(p2 == value.get<test_type>());

        // check if mismatching references throw correctly
        CHECK_THROWS_AS(value.get_ref<json::object_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::object_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is number");
        CHECK_THROWS_AS(value.get_ref<json::array_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::array_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is number");
        CHECK_THROWS_AS(value.get_ref<json::string_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::string_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is number");
        CHECK_THROWS_AS(value.get_ref<json::boolean_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::boolean_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is number");
        CHECK_NOTHROW(value.get_ref<json::number_integer_t&>());
        CHECK_THROWS_AS(value.get_ref<json::number_unsigned_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::number_unsigned_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is number");
        CHECK_THROWS_AS(value.get_ref<json::number_float_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::number_float_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is number");
    }

    SECTION("reference access to number_unsigned_t")
    {
        using test_type = json::number_unsigned_t;
        json value = 23u;

        // check if references are returned correctly
        test_type& p1 = value.get_ref<test_type&>();
        CHECK(&p1 == value.get_ptr<test_type*>());
        CHECK(p1 == value.get<test_type>());

        const test_type& p2 = value.get_ref<const test_type&>();
        CHECK(&p2 == value.get_ptr<const test_type*>());
        CHECK(p2 == value.get<test_type>());

        // check if mismatching references throw correctly
        CHECK_THROWS_AS(value.get_ref<json::object_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::object_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is number");
        CHECK_THROWS_AS(value.get_ref<json::array_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::array_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is number");
        CHECK_THROWS_AS(value.get_ref<json::string_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::string_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is number");
        CHECK_THROWS_AS(value.get_ref<json::boolean_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::boolean_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is number");
        //CHECK_THROWS_AS(value.get_ref<json::number_integer_t&>(), json::type_error&);
        //CHECK_THROWS_WITH(value.get_ref<json::number_integer_t&>(),
        //    "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is number");
        CHECK_NOTHROW(value.get_ref<json::number_unsigned_t&>());
        CHECK_THROWS_AS(value.get_ref<json::number_float_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::number_float_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is number");
    }

    SECTION("reference access to number_float_t")
    {
        using test_type = json::number_float_t;
        json value = 42.23;

        // check if references are returned correctly
        test_type& p1 = value.get_ref<test_type&>();
        CHECK(&p1 == value.get_ptr<test_type*>());
        CHECK(p1 == value.get<test_type>());

        const test_type& p2 = value.get_ref<const test_type&>();
        CHECK(&p2 == value.get_ptr<const test_type*>());
        CHECK(p2 == value.get<test_type>());

        // check if mismatching references throw correctly
        CHECK_THROWS_AS(value.get_ref<json::object_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::object_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is number");
        CHECK_THROWS_AS(value.get_ref<json::array_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::array_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is number");
        CHECK_THROWS_AS(value.get_ref<json::string_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::string_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is number");
        CHECK_THROWS_AS(value.get_ref<json::boolean_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::boolean_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is number");
        CHECK_THROWS_AS(value.get_ref<json::number_integer_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::number_integer_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is number");
        CHECK_THROWS_AS(value.get_ref<json::number_unsigned_t&>(), json::type_error&);
        CHECK_THROWS_WITH(value.get_ref<json::number_unsigned_t&>(),
                          "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is number");
        CHECK_NOTHROW(value.get_ref<json::number_float_t&>());
    }
}
