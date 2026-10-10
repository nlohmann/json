//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// This file contains the C++20-only part of unit-json_pointer.cpp (JSON pointer comparison
// with C++20 rewritten candidates and operator<=>, and char8_t literals). It is kept in a
// separate translation unit so the (much larger) unit-json_pointer.cpp is built for C++11
// only and not rebuilt for every C++ standard.

#include "doctest_compatibility.h"

// capture whether JSON_DELETE_DEPRECATED_FUNCTIONS was enabled on the command
// line *before* including json.hpp, since the library #undefs it once the header
// has been fully processed (see include/nlohmann/detail/macro_unscope.hpp); the
// tests of deprecated functions are skipped if these functions are deleted
#if defined(JSON_DELETE_DEPRECATED_FUNCTIONS) && (JSON_DELETE_DEPRECATED_FUNCTIONS == 1)
    #define JSON_TEST_DEPRECATED_FUNCTIONS_DELETED
#endif

#include <nlohmann/json.hpp>
using nlohmann::json;
#ifdef JSON_TEST_NO_GLOBAL_UDLS
    using namespace nlohmann::literals; // NOLINT(google-build-using-namespace)
#endif

#ifdef JSON_HAS_CPP_20
#if JSON_HAS_THREE_WAY_COMPARISON
    #include <compare>
#endif
#include <string>
#include <type_traits>

TEST_CASE("JSON pointers (C++20)")
{
    SECTION("equality comparison")
    {
        std::string ptr_string{"/foo/bar"};
        auto ptr1 = json::json_pointer(ptr_string);
        auto ptr2 = json::json_pointer(ptr_string);

        CHECK(ptr1 == ptr2);

        CHECK_FALSE(ptr1 != ptr2);

#ifndef JSON_TEST_DEPRECATED_FUNCTIONS_DELETED
        const char* ptr_cpstring = "/foo/bar";
        const char ptr_castring[] = "/foo/bar"; // NOLINT(misc-const-correctness,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,cppcoreguidelines-avoid-c-arrays)

        CHECK(ptr1 == "/foo/bar");
        CHECK(ptr1 == ptr_cpstring);
        CHECK(ptr1 == ptr_castring);
        CHECK(ptr1 == ptr_string);

        CHECK("/foo/bar" == ptr1);
        CHECK(ptr_cpstring == ptr1);
        CHECK(ptr_castring == ptr1);
        CHECK(ptr_string == ptr1);

        CHECK_FALSE(ptr1 != "/foo/bar");
        CHECK_FALSE(ptr1 != ptr_cpstring);
        CHECK_FALSE(ptr1 != ptr_castring);
        CHECK_FALSE(ptr1 != ptr_string);

        CHECK_FALSE("/foo/bar" != ptr1);
        CHECK_FALSE(ptr_cpstring != ptr1);
        CHECK_FALSE(ptr_castring != ptr1);
        CHECK_FALSE(ptr_string != ptr1);

        SECTION("exceptions")
        {
            CHECK_THROWS_WITH_AS(ptr1 == "foo",
                                 "[json.exception.parse_error.107] parse error at byte 1: JSON pointer must be empty or begin with '/' - was: 'foo'", json::parse_error&);
            CHECK_THROWS_WITH_AS("foo" == ptr1,
                                 "[json.exception.parse_error.107] parse error at byte 1: JSON pointer must be empty or begin with '/' - was: 'foo'", json::parse_error&);
            CHECK_THROWS_WITH_AS(ptr1 == "/~~",
                                 "[json.exception.parse_error.108] parse error: escape character '~' must be followed with '0' or '1'", json::parse_error&);
            CHECK_THROWS_WITH_AS("/~~" == ptr1,
                                 "[json.exception.parse_error.108] parse error: escape character '~' must be followed with '0' or '1'", json::parse_error&);
        }
#endif
    }

    SECTION("less-than comparison")
    {
        auto ptr1 = json::json_pointer("/foo/a");
        auto ptr2 = json::json_pointer("/foo/b");

#if JSON_HAS_THREE_WAY_COMPARISON
        CHECK((ptr1 <=> ptr2) == std::strong_ordering::less); // *NOPAD*
        CHECK(ptr2 > ptr1);
#endif
    }

    SECTION("backwards compatibility and mixing")
    {
        json j = R"(
        {
            "foo": ["bar", "baz"]
        }
        )"_json;

        using nlohmann::ordered_json;
        using json_ptr_str = nlohmann::json_pointer<std::string>;
        using json_ptr_j = nlohmann::json_pointer<json>;
        using json_ptr_oj = nlohmann::json_pointer<ordered_json>;

        std::string const ptr_string{"/foo/0"};
        json_ptr_str ptr{ptr_string};
        json_ptr_j ptr_j{ptr_string};
        json_ptr_oj ptr_oj{ptr_string};

        SECTION("equality comparison")
        {
            CHECK(ptr == ptr_j);
            CHECK(ptr == ptr_oj);
            CHECK(ptr_j == ptr);
            CHECK(ptr_j == ptr_oj);
            CHECK(ptr_oj == ptr_j);
            CHECK(ptr_oj == ptr);

            CHECK_FALSE(ptr != ptr_j);
            CHECK_FALSE(ptr != ptr_oj);
            CHECK_FALSE(ptr_j != ptr);
            CHECK_FALSE(ptr_j != ptr_oj);
            CHECK_FALSE(ptr_oj != ptr_j);
            CHECK_FALSE(ptr_oj != ptr);
        }
    }

#if defined(__cpp_char8_t)
    SECTION("Using _json_pointer with char8_t literals #4945")
    {
        const json j = R"({"a": {"b": {"c": 123}}})"_json;
        const auto p1 = "/a/b/c"_json_pointer;
        CHECK(j[p1] == 123);

        const auto p2 = u8"/a/b/c"_json_pointer;
        CHECK(j[p2] == 123);
    }
#endif
}

#endif
