//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.11.3
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013 - 2025 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

TEST_CASE("pointer access")
{
    SECTION("pointer access to object_t")
    {
        using test_type = json::object_t;
        json value = {{"one", 1}, {"two", 2}};

        // check if pointers are returned correctly
        test_type* p1 = value.get_ptr<test_type*>();
        CHECK(p1 == value.get_ptr<test_type*>());
        CHECK(*p1 == value.get<test_type>());

        const test_type* p2 = value.get_ptr<const test_type*>();
        CHECK(p2 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p3 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<json::object_t*>() != nullptr);
        CHECK(value.get_ptr<json::array_t*>() == nullptr);
        CHECK(value.get_ptr<json::string_t*>() == nullptr);
        CHECK(value.get_ptr<json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_unsigned_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_float_t*>() == nullptr);
        CHECK(value.get_ptr<json::binary_t*>() == nullptr);
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
        CHECK(p2 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p3 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<const json::object_t*>() != nullptr);
        CHECK(value.get_ptr<const json::array_t*>() == nullptr);
        CHECK(value.get_ptr<const json::string_t*>() == nullptr);
        CHECK(value.get_ptr<const json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_unsigned_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_float_t*>() == nullptr);
        CHECK(value.get_ptr<const json::binary_t*>() == nullptr);
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
        CHECK(p2 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p3 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<json::object_t*>() == nullptr);
        CHECK(value.get_ptr<json::array_t*>() != nullptr);
        CHECK(value.get_ptr<json::string_t*>() == nullptr);
        CHECK(value.get_ptr<json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_unsigned_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_float_t*>() == nullptr);
        CHECK(value.get_ptr<json::binary_t*>() == nullptr);
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
        CHECK(p2 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p3 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<const json::object_t*>() == nullptr);
        CHECK(value.get_ptr<const json::array_t*>() != nullptr);
        CHECK(value.get_ptr<const json::string_t*>() == nullptr);
        CHECK(value.get_ptr<const json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_unsigned_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_float_t*>() == nullptr);
        CHECK(value.get_ptr<const json::binary_t*>() == nullptr);
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
        CHECK(p2 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p3 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<json::object_t*>() == nullptr);
        CHECK(value.get_ptr<json::array_t*>() == nullptr);
        CHECK(value.get_ptr<json::string_t*>() != nullptr);
        CHECK(value.get_ptr<json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_unsigned_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_float_t*>() == nullptr);
        CHECK(value.get_ptr<json::binary_t*>() == nullptr);
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
        CHECK(p2 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p3 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<const json::object_t*>() == nullptr);
        CHECK(value.get_ptr<const json::array_t*>() == nullptr);
        CHECK(value.get_ptr<const json::string_t*>() != nullptr);
        CHECK(value.get_ptr<const json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_unsigned_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_float_t*>() == nullptr);
        CHECK(value.get_ptr<const json::binary_t*>() == nullptr);
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
        CHECK(p2 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p3 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<json::object_t*>() == nullptr);
        CHECK(value.get_ptr<json::array_t*>() == nullptr);
        CHECK(value.get_ptr<json::string_t*>() == nullptr);
        CHECK(value.get_ptr<json::boolean_t*>() != nullptr);
        CHECK(value.get_ptr<json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_unsigned_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_float_t*>() == nullptr);
        CHECK(value.get_ptr<json::binary_t*>() == nullptr);
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
        CHECK(p2 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p3 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<const json::object_t*>() == nullptr);
        CHECK(value.get_ptr<const json::array_t*>() == nullptr);
        CHECK(value.get_ptr<const json::string_t*>() == nullptr);
        CHECK(value.get_ptr<const json::boolean_t*>() != nullptr);
        CHECK(value.get_ptr<const json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_unsigned_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_float_t*>() == nullptr);
        CHECK(value.get_ptr<const json::binary_t*>() == nullptr);
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
        CHECK(p2 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p3 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<json::object_t*>() == nullptr);
        CHECK(value.get_ptr<json::array_t*>() == nullptr);
        CHECK(value.get_ptr<json::string_t*>() == nullptr);
        CHECK(value.get_ptr<json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_integer_t*>() != nullptr);
        CHECK(value.get_ptr<json::number_unsigned_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_float_t*>() == nullptr);
        CHECK(value.get_ptr<json::binary_t*>() == nullptr);
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
        CHECK(p2 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p3 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<const json::object_t*>() == nullptr);
        CHECK(value.get_ptr<const json::array_t*>() == nullptr);
        CHECK(value.get_ptr<const json::string_t*>() == nullptr);
        CHECK(value.get_ptr<const json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_integer_t*>() != nullptr);
        CHECK(value.get_ptr<const json::number_unsigned_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_float_t*>() == nullptr);
        CHECK(value.get_ptr<const json::binary_t*>() == nullptr);
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
        CHECK(p2 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p3 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<json::object_t*>() == nullptr);
        CHECK(value.get_ptr<json::array_t*>() == nullptr);
        CHECK(value.get_ptr<json::string_t*>() == nullptr);
        CHECK(value.get_ptr<json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_unsigned_t*>() != nullptr);
        CHECK(value.get_ptr<json::number_float_t*>() == nullptr);
        CHECK(value.get_ptr<json::binary_t*>() == nullptr);
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
        CHECK(p2 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p3 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<const json::object_t*>() == nullptr);
        CHECK(value.get_ptr<const json::array_t*>() == nullptr);
        CHECK(value.get_ptr<const json::string_t*>() == nullptr);
        CHECK(value.get_ptr<const json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_unsigned_t*>() != nullptr);
        CHECK(value.get_ptr<const json::number_float_t*>() == nullptr);
        CHECK(value.get_ptr<const json::binary_t*>() == nullptr);
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
        CHECK(p2 == value.get_ptr<const test_type*>());
        CHECK(*p2 == Approx(value.get<test_type>()));

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p3 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == Approx(value.get<test_type>()));

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<json::object_t*>() == nullptr);
        CHECK(value.get_ptr<json::array_t*>() == nullptr);
        CHECK(value.get_ptr<json::string_t*>() == nullptr);
        CHECK(value.get_ptr<json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_unsigned_t*>() == nullptr);
        CHECK(value.get_ptr<json::number_float_t*>() != nullptr);
        CHECK(value.get_ptr<json::binary_t*>() == nullptr);
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
        CHECK(p2 == value.get_ptr<const test_type*>());
        CHECK(*p2 == Approx(value.get<test_type>()));

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p3 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == Approx(value.get<test_type>()));

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<const json::object_t*>() == nullptr);
        CHECK(value.get_ptr<const json::array_t*>() == nullptr);
        CHECK(value.get_ptr<const json::string_t*>() == nullptr);
        CHECK(value.get_ptr<const json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_unsigned_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_float_t*>() != nullptr);
        CHECK(value.get_ptr<const json::binary_t*>() == nullptr);
    }

    SECTION("pointer access to const binary_t")
    {
        using test_type = const json::binary_t;
        const json value = json::binary({1, 2, 3});

        // check if pointers are returned correctly
        test_type* p1 = value.get_ptr<test_type*>();
        CHECK(p1 == value.get_ptr<test_type*>());
        CHECK(*p1 == value.get<test_type>());

        const test_type* p2 = value.get_ptr<const test_type*>();
        CHECK(p2 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p3 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<const json::object_t*>() == nullptr);
        CHECK(value.get_ptr<const json::array_t*>() == nullptr);
        CHECK(value.get_ptr<const json::string_t*>() == nullptr);
        CHECK(value.get_ptr<const json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_unsigned_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_float_t*>() == nullptr);
        CHECK(value.get_ptr<const json::binary_t*>() != nullptr);
    }

    SECTION("pointer access to const binary_t")
    {
        using test_type = const json::binary_t;
        const json value = json::binary({});

        // check if pointers are returned correctly
        test_type* p1 = value.get_ptr<test_type*>();
        CHECK(p1 == value.get_ptr<test_type*>());
        CHECK(*p1 == value.get<test_type>());

        const test_type* p2 = value.get_ptr<const test_type*>();
        CHECK(p2 == value.get_ptr<const test_type*>());
        CHECK(*p2 == value.get<test_type>());

        const test_type* const p3 = value.get_ptr<const test_type* const>();
        CHECK(p3 == value.get_ptr<const test_type* const>());
        CHECK(*p3 == value.get<test_type>());

        // check if null pointers are returned correctly
        CHECK(value.get_ptr<const json::object_t*>() == nullptr);
        CHECK(value.get_ptr<const json::array_t*>() == nullptr);
        CHECK(value.get_ptr<const json::string_t*>() == nullptr);
        CHECK(value.get_ptr<const json::boolean_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_integer_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_unsigned_t*>() == nullptr);
        CHECK(value.get_ptr<const json::number_float_t*>() == nullptr);
        CHECK(value.get_ptr<const json::binary_t*>() != nullptr);
    }
}
