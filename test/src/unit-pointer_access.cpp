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

TEST_CASE("pointer access")
{
    // create a JSON value with different types
    json json_types =
    {
        {"boolean", true},
        {
            "number", {
                {"integer", 42},
                {"unsigned", 42u},
                {"floating-point", 17.23}
            }
        },
        {"string", "Hello, world!"},
        {"array", {1, 2, 3, 4, 5}},
        {"null", nullptr}
    };

    SECTION("pointer access to object_t")
    {
        using test_type = json::object_t;
        json value = {{"one", 1}, {"two", 2}};

        // check if pointers are returned correctly
        test_type* p1 = value.get_ptr<test_type*>();
        CHECK(p1 == value.get_ptr<test_type*>());
        CHECK(*p1 == value.get<test_type>());

        const test_type* p2 = value.get_ptr<const test_type*>();
        CHECK(p1 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p1 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<json::object_t*>() != nullptr);
        CHECK(value.get_ptr<json::array_t*>() == nullptr);
        CHECK(value.get_ptr<json::string_t*>() == nullptr);
        CHECK(value.get_ptr<json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_unsigned_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_float_t*>() == nullptr);
    }

    SECTION("pointer access to const object_t")
    {
        using test_type = const json::object_t;
        const json value = {{"one", 1}, {"two", 2}};

        // check if pointers are returned correctly
        test_type* p1 = value.get_ptr<test_type*>();
        CHECK(p1 == value.get_ptr<test_type*>());
        CHECK(*p1 == value.get<test_type>());

        const test_type* p2 = value.get_ptr<const test_type*>();
        CHECK(p1 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p1 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<const json::object_t*>() != nullptr);
        CHECK(value.get_ptr<const json::array_t*>() == nullptr);
        CHECK(value.get_ptr<const json::string_t*>() == nullptr);
        CHECK(value.get_ptr<const json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_unsigned_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_float_t*>() == nullptr);
    }

    SECTION("pointer access to array_t")
    {
        using test_type = json::array_t;
        json value = {1, 2, 3, 4};

        // check if pointers are returned correctly
        test_type* p1 = value.get_ptr<test_type*>();
        CHECK(p1 == value.get_ptr<test_type*>());
        CHECK(*p1 == value.get<test_type>());

        const test_type* p2 = value.get_ptr<const test_type*>();
        CHECK(p1 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p1 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<json::object_t*>() == nullptr);
        CHECK(value.get_ptr<json::array_t*>() != nullptr);
        CHECK(value.get_ptr<json::string_t*>() == nullptr);
        CHECK(value.get_ptr<json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_unsigned_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_float_t*>() == nullptr);
    }

    SECTION("pointer access to const array_t")
    {
        using test_type = const json::array_t;
        const json value = {1, 2, 3, 4};

        // check if pointers are returned correctly
        test_type* p1 = value.get_ptr<test_type*>();
        CHECK(p1 == value.get_ptr<test_type*>());
        CHECK(*p1 == value.get<test_type>());

        const test_type* p2 = value.get_ptr<const test_type*>();
        CHECK(p1 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p1 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<const json::object_t*>() == nullptr);
        CHECK(value.get_ptr<const json::array_t*>() != nullptr);
        CHECK(value.get_ptr<const json::string_t*>() == nullptr);
        CHECK(value.get_ptr<const json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_unsigned_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_float_t*>() == nullptr);
    }

    SECTION("pointer access to string_t")
    {
        using test_type = json::string_t;
        json value = "hello";

        // check if pointers are returned correctly
        test_type* p1 = value.get_ptr<test_type*>();
        CHECK(p1 == value.get_ptr<test_type*>());
        CHECK(*p1 == value.get<test_type>());

        const test_type* p2 = value.get_ptr<const test_type*>();
        CHECK(p1 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p1 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<json::object_t*>() == nullptr);
        CHECK(value.get_ptr<json::array_t*>() == nullptr);
        CHECK(value.get_ptr<json::string_t*>() != nullptr);
        CHECK(value.get_ptr<json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_unsigned_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_float_t*>() == nullptr);
    }

    SECTION("pointer access to const string_t")
    {
        using test_type = const json::string_t;
        const json value = "hello";

        // check if pointers are returned correctly
        test_type* p1 = value.get_ptr<test_type*>();
        CHECK(p1 == value.get_ptr<test_type*>());
        CHECK(*p1 == value.get<test_type>());

        const test_type* p2 = value.get_ptr<const test_type*>();
        CHECK(p1 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p1 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<const json::object_t*>() == nullptr);
        CHECK(value.get_ptr<const json::array_t*>() == nullptr);
        CHECK(value.get_ptr<const json::string_t*>() != nullptr);
        CHECK(value.get_ptr<const json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_unsigned_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_float_t*>() == nullptr);
    }

    SECTION("pointer access to boolean_t")
    {
        using test_type = json::boolean_t;
        json value = false;

        // check if pointers are returned correctly
        test_type* p1 = value.get_ptr<test_type*>();
        CHECK(p1 == value.get_ptr<test_type*>());
        CHECK(*p1 == value.get<test_type>());

        const test_type* p2 = value.get_ptr<const test_type*>();
        CHECK(p1 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p1 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<json::object_t*>() == nullptr);
        CHECK(value.get_ptr<json::array_t*>() == nullptr);
        CHECK(value.get_ptr<json::string_t*>() == nullptr);
        CHECK(value.get_ptr<json::boolean_t*>() != nullptr);
        CHECK(value.get_ptr<json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_unsigned_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_float_t*>() == nullptr);
    }

    SECTION("pointer access to const boolean_t")
    {
        using test_type = const json::boolean_t;
        const json value = false;

        // check if pointers are returned correctly
        test_type* p1 = value.get_ptr<test_type*>();
        CHECK(p1 == value.get_ptr<test_type*>());
        //CHECK(*p1 == value.get<test_type>());

        const test_type* p2 = value.get_ptr<const test_type*>();
        CHECK(p1 == value.get_ptr<const test_type*>());
        //CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p1 == value.get_ptr<const test_type* const>());
        //CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<const json::object_t*>() == nullptr);
        CHECK(value.get_ptr<const json::array_t*>() == nullptr);
        CHECK(value.get_ptr<const json::string_t*>() == nullptr);
        CHECK(value.get_ptr<const json::boolean_t*>() != nullptr);
        CHECK(value.get_ptr<const json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_unsigned_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_float_t*>() == nullptr);
    }

    SECTION("pointer access to number_integer_t")
    {
        using test_type = json::number_integer_t;
        json value = 23;

        // check if pointers are returned correctly
        test_type* p1 = value.get_ptr<test_type*>();
        CHECK(p1 == value.get_ptr<test_type*>());
        CHECK(*p1 == value.get<test_type>());

        const test_type* p2 = value.get_ptr<const test_type*>();
        CHECK(p1 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p1 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<json::object_t*>() == nullptr);
        CHECK(value.get_ptr<json::array_t*>() == nullptr);
        CHECK(value.get_ptr<json::string_t*>() == nullptr);
        CHECK(value.get_ptr<json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_integer_t*>() != nullptr);
        CHECK(value.get_ptr<json::number_unsigned_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_float_t*>() == nullptr);
    }

    SECTION("pointer access to const number_integer_t")
    {
        using test_type = const json::number_integer_t;
        const json value = 23;

        // check if pointers are returned correctly
        test_type* p1 = value.get_ptr<test_type*>();
        CHECK(p1 == value.get_ptr<test_type*>());
        CHECK(*p1 == value.get<test_type>());

        const test_type* p2 = value.get_ptr<const test_type*>();
        CHECK(p1 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p1 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<const json::object_t*>() == nullptr);
        CHECK(value.get_ptr<const json::array_t*>() == nullptr);
        CHECK(value.get_ptr<const json::string_t*>() == nullptr);
        CHECK(value.get_ptr<const json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_integer_t*>() != nullptr);
        CHECK(value.get_ptr<const json::number_unsigned_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_float_t*>() == nullptr);
    }

    SECTION("pointer access to number_unsigned_t")
    {
        using test_type = json::number_unsigned_t;
        json value = 23u;

        // check if pointers are returned correctly
        test_type* p1 = value.get_ptr<test_type*>();
        CHECK(p1 == value.get_ptr<test_type*>());
        CHECK(*p1 == value.get<test_type>());

        const test_type* p2 = value.get_ptr<const test_type*>();
        CHECK(p1 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p1 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<json::object_t*>() == nullptr);
        CHECK(value.get_ptr<json::array_t*>() == nullptr);
        CHECK(value.get_ptr<json::string_t*>() == nullptr);
        CHECK(value.get_ptr<json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_integer_t*>() != nullptr);
        CHECK(value.get_ptr<json::number_unsigned_t*>() != nullptr);
        CHECK(value.get_ptr<json::number_float_t*>() == nullptr);
    }

    SECTION("pointer access to const number_unsigned_t")
    {
        using test_type = const json::number_unsigned_t;
        const json value = 23u;

        // check if pointers are returned correctly
        test_type* p1 = value.get_ptr<test_type*>();
        CHECK(p1 == value.get_ptr<test_type*>());
        CHECK(*p1 == value.get<test_type>());

        const test_type* p2 = value.get_ptr<const test_type*>();
        CHECK(p1 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p1 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<const json::object_t*>() == nullptr);
        CHECK(value.get_ptr<const json::array_t*>() == nullptr);
        CHECK(value.get_ptr<const json::string_t*>() == nullptr);
        CHECK(value.get_ptr<const json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_integer_t*>() != nullptr);
        CHECK(value.get_ptr<const json::number_unsigned_t*>() != nullptr);
        CHECK(value.get_ptr<const json::number_float_t*>() == nullptr);
    }

    SECTION("pointer access to number_float_t")
    {
        using test_type = json::number_float_t;
        json value = 42.23;

        // check if pointers are returned correctly
        test_type* p1 = value.get_ptr<test_type*>();
        CHECK(p1 == value.get_ptr<test_type*>());
        CHECK(*p1 == Approx(value.get<test_type>()));

        const test_type* p2 = value.get_ptr<const test_type*>();
        CHECK(p1 == value.get_ptr<const test_type*>());
        CHECK(*p2 == Approx(value.get<test_type>()));

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p1 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == Approx(value.get<test_type>()));

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<json::object_t*>() == nullptr);
        CHECK(value.get_ptr<json::array_t*>() == nullptr);
        CHECK(value.get_ptr<json::string_t*>() == nullptr);
        CHECK(value.get_ptr<json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_unsigned_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_float_t*>() != nullptr);
    }

    SECTION("pointer access to const number_float_t")
    {
        using test_type = const json::number_float_t;
        const json value = 42.23;

        // check if pointers are returned correctly
        test_type* p1 = value.get_ptr<test_type*>();
        CHECK(p1 == value.get_ptr<test_type*>());
        CHECK(*p1 == Approx(value.get<test_type>()));

        const test_type* p2 = value.get_ptr<const test_type*>();
        CHECK(p1 == value.get_ptr<const test_type*>());
        CHECK(*p2 == Approx(value.get<test_type>()));

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p1 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == Approx(value.get<test_type>()));

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<const json::object_t*>() == nullptr);
        CHECK(value.get_ptr<const json::array_t*>() == nullptr);
        CHECK(value.get_ptr<const json::string_t*>() == nullptr);
        CHECK(value.get_ptr<const json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_unsigned_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_float_t*>() != nullptr);
    }
}
