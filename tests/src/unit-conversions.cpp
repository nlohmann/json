//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2025 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// cmake/test.cmake selects the C++ standard versions with which to build a
// unit test based on the presence of JSON_HAS_CPP_<VERSION> macros.
// When using macros that are only defined for particular versions of the standard
// (e.g., JSON_HAS_FILESYSTEM for C++17 and up), please mention the corresponding
// version macro in a comment close by, like this:
// JSON_HAS_CPP_<VERSION> (do not remove; see note at top of file)

#include "doctest_compatibility.h"

// skip tests if JSON_DisableEnumSerialization=ON (#4384)
#if defined(JSON_DISABLE_ENUM_SERIALIZATION) && (JSON_DISABLE_ENUM_SERIALIZATION == 1)
    #define SKIP_TESTS_FOR_ENUM_SERIALIZATION
#endif

#define JSON_TESTS_PRIVATE
#include <nlohmann/json.hpp>
using nlohmann::json;

#include <deque>
#include <forward_list>
#include <list>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <valarray>

// NLOHMANN_JSON_SERIALIZE_ENUM uses a static std::pair
DOCTEST_CLANG_SUPPRESS_WARNING_PUSH
DOCTEST_CLANG_SUPPRESS_WARNING("-Wexit-time-destructors")

#if (defined(__cplusplus) && __cplusplus >= 201703L) || (defined(_HAS_CXX17) && _HAS_CXX17 == 1) // fix for issue #464
    #define JSON_HAS_CPP_17
    #define JSON_HAS_CPP_14
#elif (defined(__cplusplus) && __cplusplus >= 201402L) || (defined(_HAS_CXX14) && _HAS_CXX14 == 1)
    #define JSON_HAS_CPP_14
#endif

#ifdef JSON_HAS_CPP_17
    #if __has_include(<optional>)
        #include <optional>
    #elif __has_include(<experimental/optional>)
        #include <experimental/optional>
    #endif
#endif

#if defined(JSON_HAS_CPP_17)
    #include <string_view>
#endif

TEST_CASE("value conversion")
{
    SECTION("get an object (explicit)")
    {
        const json::object_t o_reference = {{"object", json::object()},
            {"array", {1, 2, 3, 4}},
            {"number", 42},
            {"boolean", false},
            {"null", nullptr},
            {"string", "Hello world"}
        };
        json j(o_reference);

        SECTION("json::object_t")
        {
            json::object_t const o = j.get<json::object_t>();
            CHECK(json(o) == j);
        }

        SECTION("std::map<json::string_t, json>")
        {
            const std::map<json::string_t, json> o =
                j.get<std::map<json::string_t, json>>();
            CHECK(json(o) == j);
        }

        SECTION("std::multimap<json::string_t, json>")
        {
            const std::multimap<json::string_t, json> o =
                j.get<std::multimap<json::string_t, json>>();
            CHECK(json(o) == j);
        }

        SECTION("std::unordered_map<json::string_t, json>")
        {
            const std::unordered_map<json::string_t, json> o =
                j.get<std::unordered_map<json::string_t, json>>();
            CHECK(json(o) == j);
        }

        SECTION("std::unordered_multimap<json::string_t, json>")
        {
            const std::unordered_multimap<json::string_t, json> o =
                j.get<std::unordered_multimap<json::string_t, json>>();
            CHECK(json(o) == j);
        }

        SECTION("exception in case of a non-object type")
        {
            CHECK_THROWS_WITH_AS(
                json(json::value_t::null).get<json::object_t>(),
                "[json.exception.type_error.302] type must be object, but is null", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::array).get<json::object_t>(),
                "[json.exception.type_error.302] type must be object, but is array", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::string).get<json::object_t>(),
                "[json.exception.type_error.302] type must be object, but is string", json::type_error&);
            CHECK_THROWS_WITH_AS(json(json::value_t::boolean).get<json::object_t>(),
                                 "[json.exception.type_error.302] type must be object, "
                                 "but is boolean", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::number_integer).get<json::object_t>(),
                "[json.exception.type_error.302] type must be object, but is number", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::number_unsigned).get<json::object_t>(),
                "[json.exception.type_error.302] type must be object, but is number", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::number_float).get<json::object_t>(),
                "[json.exception.type_error.302] type must be object, but is number", json::type_error&);
        }
    }

    SECTION("get an object (explicit, get_to)")
    {
        const json::object_t o_reference = {{"object", json::object()},
            {"array", {1, 2, 3, 4}},
            {"number", 42},
            {"boolean", false},
            {"null", nullptr},
            {"string", "Hello world"}
        };
        json j(o_reference);

        SECTION("json::object_t")
        {
            json::object_t o = {{"previous", "value"}};
            j.get_to(o);
            CHECK(json(o) == j);
        }

        SECTION("std::map<json::string_t, json>")
        {
            std::map<json::string_t, json> o{{"previous", "value"}};
            j.get_to(o);
            CHECK(json(o) == j);
        }

        SECTION("std::multimap<json::string_t, json>")
        {
            std::multimap<json::string_t, json> o{{"previous", "value"}};
            j.get_to(o);
            CHECK(json(o) == j);
        }

        SECTION("std::unordered_map<json::string_t, json>")
        {
            std::unordered_map<json::string_t, json> o{{"previous", "value"}};
            j.get_to(o);
            CHECK(json(o) == j);
        }

        SECTION("std::unordered_multimap<json::string_t, json>")
        {
            std::unordered_multimap<json::string_t, json> o{{"previous", "value"}};
            j.get_to(o);
            CHECK(json(o) == j);
        }
    }

#if JSON_USE_IMPLICIT_CONVERSIONS

    SECTION("get an object (implicit)")
    {
        const json::object_t o_reference = {{"object", json::object()},
            {"array", {1, 2, 3, 4}},
            {"number", 42},
            {"boolean", false},
            {"null", nullptr},
            {"string", "Hello world"}
        };
        json j(o_reference);

        SECTION("json::object_t")
        {
            const json::object_t o = j;
            CHECK(json(o) == j);
        }

        SECTION("std::map<json::string_t, json>")
        {
            const std::map<json::string_t, json> o = j;
            CHECK(json(o) == j);
        }

        SECTION("std::multimap<json::string_t, json>")
        {
            const std::multimap<json::string_t, json> o = j;
            CHECK(json(o) == j);
        }

        SECTION("std::unordered_map<json::string_t, json>")
        {
            const std::unordered_map<json::string_t, json> o = j;
            CHECK(json(o) == j);
        }

        SECTION("std::unordered_multimap<json::string_t, json>")
        {
            const std::unordered_multimap<json::string_t, json> o = j;
            CHECK(json(o) == j);
        }
    }
#endif

    SECTION("get an array (explicit)")
    {
        const json::array_t a_reference{json(1),     json(1u),       json(2.2),
                                        json(false), json("string"), json()};
        json j(a_reference);

        SECTION("json::array_t")
        {
            const json::array_t a = j.get<json::array_t>();
            CHECK(json(a) == j);
        }

        SECTION("std::list<json>")
        {
            const std::list<json> a = j.get<std::list<json>>();
            CHECK(json(a) == j);
        }

        SECTION("std::forward_list<json>")
        {
            const std::forward_list<json> a = j.get<std::forward_list<json>>();
            CHECK(json(a) == j);

            CHECK_THROWS_WITH_AS(
                json(json::value_t::null).get<std::forward_list<json>>(),
                "[json.exception.type_error.302] type must be array, but is null", json::type_error&);
        }

        SECTION("std::vector<json>")
        {
            const std::vector<json> a = j.get<std::vector<json>>();
            CHECK(json(a) == j);

            CHECK_THROWS_WITH_AS(
                json(json::value_t::null).get<std::vector<json>>(),
                "[json.exception.type_error.302] type must be array, but is null", json::type_error&);

#if !defined(JSON_NOEXCEPTION)
            SECTION("reserve is called on containers that supports it")
            {
                // make sure all values are properly copied
                const json j2({1, 2, 3, 4, 5, 6, 7, 8, 9, 10});
                auto v2 = j2.get<std::vector<int>>();
                CHECK(v2.size() == 10);
            }
#endif
        }

        SECTION("built-in arrays")
        {
            const char str[] = "a string"; // NOLINT(misc-const-correctness,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
            const int nbs[] = {0, 1, 2}; // NOLINT(misc-const-correctness,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)

            const json j2 = nbs;
            const json j3 = str;

            auto v = j2.get<std::vector<int>>();
            auto s = j3.get<std::string>();
            CHECK(std::equal(v.begin(), v.end(), std::begin(nbs)));
            CHECK(s == str);
        }

        SECTION("std::deque<json>")
        {
            const std::deque<json> a = j.get<std::deque<json>>();
            CHECK(json(a) == j);
        }

        SECTION("exception in case of a non-array type")
        {
            CHECK_THROWS_WITH_AS(
                json(json::value_t::object).get<std::vector<int>>(),
                "[json.exception.type_error.302] type must be array, but is object", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::null).get<json::array_t>(),
                "[json.exception.type_error.302] type must be array, but is null", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::object).get<json::array_t>(),
                "[json.exception.type_error.302] type must be array, but is object", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::string).get<json::array_t>(),
                "[json.exception.type_error.302] type must be array, but is string", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::boolean).get<json::array_t>(),
                "[json.exception.type_error.302] type must be array, but is boolean", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::number_integer).get<json::array_t>(),
                "[json.exception.type_error.302] type must be array, but is number", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::number_unsigned).get<json::array_t>(),
                "[json.exception.type_error.302] type must be array, but is number", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::number_float).get<json::array_t>(),
                "[json.exception.type_error.302] type must be array, but is number", json::type_error&);
        }
    }

    SECTION("get an array (explicit, get_to)")
    {
        const json::array_t a_reference{json(1),     json(1u),       json(2.2),
                                        json(false), json("string"), json()};
        json j(a_reference);

        SECTION("json::array_t")
        {
            json::array_t a{"previous", "value"};
            j.get_to(a);
            CHECK(json(a) == j);
        }

        SECTION("std::valarray<json>")
        {
            std::valarray<json> a{"previous", "value"};
            j.get_to(a);
            CHECK(json(a) == j);
        }

        SECTION("std::list<json>")
        {
            std::list<json> a{"previous", "value"};
            j.get_to(a);
            CHECK(json(a) == j);
        }

        SECTION("std::forward_list<json>")
        {
            std::forward_list<json> a{"previous", "value"};
            j.get_to(a);
            CHECK(json(a) == j);
        }

        SECTION("std::vector<json>")
        {
            std::vector<json> a{"previous", "value"};
            j.get_to(a);
            CHECK(json(a) == j);
        }

        SECTION("built-in arrays")
        {
            const int nbs[] = {0, 1, 2}; // NOLINT(misc-const-correctness,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
            int nbs2[] = {0, 0, 0}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)

            const json j2 = nbs;
            j2.get_to(nbs2);
            CHECK(std::equal(std::begin(nbs), std::end(nbs), std::begin(nbs2)));
        }

        SECTION("built-in arrays: 2D")
        {
            const int nbs[][3] = {{0, 1, 2}, {3, 4, 5}}; // NOLINT(misc-const-correctness,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
            int nbs2[][3] = {{0, 0, 0}, {0, 0, 0}}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)

            const json j2 = nbs;
            j2.get_to(nbs2);
            CHECK(std::equal(std::begin(nbs[0]), std::end(nbs[1]), std::begin(nbs2[0])));
        }

        SECTION("built-in arrays: 3D")
        {
            // NOLINTBEGIN(misc-const-correctness,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
            const int nbs[][2][3] = {\
                {{0, 1, 2}, {3, 4, 5}}, \
                {{10, 11, 12}, {13, 14, 15}}\
            };
            int nbs2[][2][3] = {\
                {{0, 0, 0}, {0, 0, 0}}, \
                {{0, 0, 0}, {0, 0, 0}}\
            };
            // NOLINTEND(misc-const-correctness,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)

            const json j2 = nbs;
            j2.get_to(nbs2);
            CHECK(std::equal(std::begin(nbs[0][0]), std::end(nbs[1][1]), std::begin(nbs2[0][0])));
        }

        SECTION("built-in arrays: 4D")
        {
            // NOLINTBEGIN(misc-const-correctness,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
            const int nbs[][2][2][3] = {\
                {
                    \
                    {{0, 1, 2}, {3, 4, 5}}, \
                    {{10, 11, 12}, {13, 14, 15}}\
                }, \
                {
                    \
                    {{20, 21, 22}, {23, 24, 25}}, \
                    {{30, 31, 32}, {33, 34, 35}}\
                }\
            };
            int nbs2[][2][2][3] = {\
                {
                    \
                    {{0, 0, 0}, {0, 0, 0}}, \
                    {{0, 0, 0}, {0, 0, 0}}\
                }, \
                {
                    \
                    {{0, 0, 0}, {0, 0, 0}}, \
                    {{0, 0, 0}, {0, 0, 0}}\
                }\
            };
            // NOLINTEND(misc-const-correctness,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)

            const json j2 = nbs;
            j2.get_to(nbs2);
            CHECK(std::equal(std::begin(nbs[0][0][0]), std::end(nbs[1][1][1]), std::begin(nbs2[0][0][0])));
        }

        SECTION("std::deque<json>")
        {
            std::deque<json> a{"previous", "value"};
            j.get_to(a);
            CHECK(json(a) == j);
        }
    }

#if JSON_USE_IMPLICIT_CONVERSIONS
    SECTION("get an array (implicit)")
    {
        const json::array_t a_reference{json(1),     json(1u),       json(2.2),
                                        json(false), json("string"), json()};
        json j(a_reference);

        SECTION("json::array_t")
        {
            const json::array_t a = j;
            CHECK(json(a) == j);
        }

        SECTION("std::list<json>")
        {
            const std::list<json> a = j;
            CHECK(json(a) == j);
        }

        SECTION("std::forward_list<json>")
        {
            const std::forward_list<json> a = j;
            CHECK(json(a) == j);
        }

        SECTION("std::vector<json>")
        {
            const std::vector<json> a = j;
            CHECK(json(a) == j);
        }

        SECTION("std::deque<json>")
        {
            const std::deque<json> a = j;
            CHECK(json(a) == j);
        }
    }
#endif

    SECTION("get a string (explicit)")
    {
        const json::string_t s_reference{"Hello world"};
        json j(s_reference);

        SECTION("string_t")
        {
            const json::string_t s = j.get<json::string_t>();
            CHECK(json(s) == j);
        }

        SECTION("std::string")
        {
            const std::string s = j.get<std::string>();
            CHECK(json(s) == j);
        }
#if defined(JSON_HAS_CPP_17)
        SECTION("std::string_view")
        {
            std::string_view const s = j.get<std::string_view>();
            CHECK(json(s) == j);
        }
#endif

        SECTION("exception in case of a non-string type")
        {
            CHECK_THROWS_WITH_AS(
                json(json::value_t::null).get<json::string_t>(),
                "[json.exception.type_error.302] type must be string, but is null", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::object).get<json::string_t>(),
                "[json.exception.type_error.302] type must be string, but is object", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::array).get<json::string_t>(),
                "[json.exception.type_error.302] type must be string, but is array", json::type_error&);
            CHECK_THROWS_WITH_AS(json(json::value_t::boolean).get<json::string_t>(),
                                 "[json.exception.type_error.302] type must be string, "
                                 "but is boolean", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::number_integer).get<json::string_t>(),
                "[json.exception.type_error.302] type must be string, but is number", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::number_unsigned).get<json::string_t>(),
                "[json.exception.type_error.302] type must be string, but is number", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::number_float).get<json::string_t>(),
                "[json.exception.type_error.302] type must be string, but is number", json::type_error&);
        }

#if defined(JSON_HAS_CPP_17)
        SECTION("exception in case of a non-string type using string_view")
        {
            CHECK_THROWS_WITH_AS(json(json::value_t::null).get<std::string_view>(),
                                 "[json.exception.type_error.302] type must be string, but is null", json::type_error&);
            CHECK_THROWS_WITH_AS(json(json::value_t::object).get<std::string_view>(),
                                 "[json.exception.type_error.302] type must be string, but is object", json::type_error&);
            CHECK_THROWS_WITH_AS(json(json::value_t::array).get<std::string_view>(),
                                 "[json.exception.type_error.302] type must be string, but is array", json::type_error&);
            CHECK_THROWS_WITH_AS(json(json::value_t::boolean).get<std::string_view>(),
                                 "[json.exception.type_error.302] type must be string, but is boolean", json::type_error&);
            CHECK_THROWS_WITH_AS(json(json::value_t::number_integer).get<std::string_view>(),
                                 "[json.exception.type_error.302] type must be string, but is number", json::type_error&);
            CHECK_THROWS_WITH_AS(json(json::value_t::number_unsigned).get<std::string_view>(),
                                 "[json.exception.type_error.302] type must be string, but is number", json::type_error&);
            CHECK_THROWS_WITH_AS(json(json::value_t::number_float).get<std::string_view>(),
                                 "[json.exception.type_error.302] type must be string, but is number", json::type_error&);
        }
#endif
    }

    SECTION("get a string (explicit, get_to)")
    {
        const json::string_t s_reference{"Hello world"};
        json j(s_reference);

        SECTION("string_t")
        {
            json::string_t s = "previous value";
            j.get_to(s);
            CHECK(json(s) == j);
        }

        SECTION("std::string")
        {
            std::string s = "previous value";
            j.get_to(s);
            CHECK(json(s) == j);
        }
#if defined(JSON_HAS_CPP_17)
        SECTION("std::string_view")
        {
            std::string const s = "previous value";
            std::string_view sv = s;
            j.get_to(sv);
            CHECK(json(sv) == j);
        }
#endif
    }

    SECTION("get null (explicit)")
    {
        std::nullptr_t n = nullptr;
        const json j(n);

        auto n2 = j.get<std::nullptr_t>();
        CHECK(n2 == n);

        CHECK_THROWS_WITH_AS(json(json::value_t::string).get<std::nullptr_t>(),
                             "[json.exception.type_error.302] type must be null, but is string", json::type_error&);
        CHECK_THROWS_WITH_AS(json(json::value_t::object).get<std::nullptr_t>(),
                             "[json.exception.type_error.302] type must be null, but is object", json::type_error&);
        CHECK_THROWS_WITH_AS(json(json::value_t::array).get<std::nullptr_t>(),
                             "[json.exception.type_error.302] type must be null, but is array", json::type_error&);
        CHECK_THROWS_WITH_AS(json(json::value_t::boolean).get<std::nullptr_t>(),
                             "[json.exception.type_error.302] type must be null, but is boolean", json::type_error&);
        CHECK_THROWS_WITH_AS(json(json::value_t::number_integer).get<std::nullptr_t>(),
                             "[json.exception.type_error.302] type must be null, but is number", json::type_error&);
        CHECK_THROWS_WITH_AS(json(json::value_t::number_unsigned).get<std::nullptr_t>(),
                             "[json.exception.type_error.302] type must be null, but is number", json::type_error&);
        CHECK_THROWS_WITH_AS(json(json::value_t::number_float).get<std::nullptr_t>(),
                             "[json.exception.type_error.302] type must be null, but is number", json::type_error&);
    }

#if JSON_USE_IMPLICIT_CONVERSIONS
    SECTION("get a string (implicit)")
    {
        const json::string_t s_reference{"Hello world"};
        json j(s_reference);

        SECTION("string_t")
        {
            const json::string_t s = j;
            CHECK(json(s) == j);
        }

#if defined(JSON_HAS_CPP_17)
        SECTION("std::string_view")
        {
            std::string_view const s = j.get<std::string_view>();
            CHECK(json(s) == j);
        }
#endif

        SECTION("std::string")
        {
            const std::string s = j;
            CHECK(json(s) == j);
        }
    }
#endif

    SECTION("get a boolean (explicit)")
    {
        const json::boolean_t b_reference{true};
        json j(b_reference);

        SECTION("boolean_t")
        {
            auto b = j.get<json::boolean_t>();
            CHECK(json(b) == j);
        }

        SECTION("uint8_t")
        {
            auto n = j.get<uint8_t>();
            CHECK(n == 1);
        }

        SECTION("bool")
        {
            const bool b = j.get<bool>();
            CHECK(json(b) == j);
        }

        SECTION("exception in case of a non-number type")
        {
            CHECK_THROWS_AS(json(json::value_t::string).get<uint8_t>(),
                            json::type_error&);

            CHECK_THROWS_WITH_AS(
                json(json::value_t::null).get<json::boolean_t>(),
                "[json.exception.type_error.302] type must be boolean, but is null", json::type_error&);
            CHECK_THROWS_WITH_AS(json(json::value_t::object).get<json::boolean_t>(),
                                 "[json.exception.type_error.302] type must be boolean, "
                                 "but is object", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::array).get<json::boolean_t>(),
                "[json.exception.type_error.302] type must be boolean, but is array", json::type_error&);
            CHECK_THROWS_WITH_AS(json(json::value_t::string).get<json::boolean_t>(),
                                 "[json.exception.type_error.302] type must be boolean, "
                                 "but is string", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::number_integer).get<json::boolean_t>(),
                "[json.exception.type_error.302] type must be boolean, but is "
                "number", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::number_unsigned).get<json::boolean_t>(),
                "[json.exception.type_error.302] type must be boolean, but is "
                "number", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::number_float).get<json::boolean_t>(),
                "[json.exception.type_error.302] type must be boolean, but is "
                "number", json::type_error&);
        }
    }

#if JSON_USE_IMPLICIT_CONVERSIONS
    SECTION("get a boolean (implicit)")
    {
        const json::boolean_t b_reference{true};
        json j(b_reference);

        SECTION("boolean_t")
        {
            const json::boolean_t b = j;
            CHECK(json(b) == j);
        }

        SECTION("bool")
        {
            const bool b = j;
            CHECK(json(b) == j);
        }
    }
#endif

    SECTION("get an integer number (explicit)")
    {
        const json::number_integer_t n_reference{42};
        json j(n_reference);
        const json::number_unsigned_t n_unsigned_reference{42u};
        json j_unsigned(n_unsigned_reference);

        SECTION("number_integer_t")
        {
            auto n = j.get<json::number_integer_t>();
            CHECK(json(n) == j);
        }

        SECTION("number_unsigned_t")
        {
            auto n = j_unsigned.get<json::number_unsigned_t>();
            CHECK(json(n) == j_unsigned);
        }

        SECTION("short")
        {
            auto n = j.get<short>();
            CHECK(json(n) == j);
        }

        SECTION("unsigned short")
        {
            auto n = j.get<unsigned short>();
            CHECK(json(n) == j);
        }

        SECTION("int")
        {
            const int n = j.get<int>();
            CHECK(json(n) == j);
        }

        SECTION("unsigned int")
        {
            auto n = j.get<unsigned int>();
            CHECK(json(n) == j);
        }

        SECTION("long")
        {
            const long n = j.get<long>();
            CHECK(json(n) == j);
        }

        SECTION("unsigned long")
        {
            auto n = j.get<unsigned long>();
            CHECK(json(n) == j);
        }

        SECTION("long long")
        {
            auto n = j.get<long long>();
            CHECK(json(n) == j);
        }

        SECTION("unsigned long long")
        {
            auto n = j.get<unsigned long long>();
            CHECK(json(n) == j);
        }

        SECTION("int8_t")
        {
            auto n = j.get<int8_t>();
            CHECK(json(n) == j);
        }

        SECTION("int16_t")
        {
            auto n = j.get<int16_t>();
            CHECK(json(n) == j);
        }

        SECTION("int32_t")
        {
            auto n = j.get<int32_t>();
            CHECK(json(n) == j);
        }

        SECTION("int64_t")
        {
            auto n = j.get<int64_t>();
            CHECK(json(n) == j);
        }

        SECTION("int8_fast_t")
        {
            auto n = j.get<int_fast8_t>();
            CHECK(json(n) == j);
        }

        SECTION("int16_fast_t")
        {
            auto n = j.get<int_fast16_t>();
            CHECK(json(n) == j);
        }

        SECTION("int32_fast_t")
        {
            auto n = j.get<int_fast32_t>();
            CHECK(json(n) == j);
        }

        SECTION("int64_fast_t")
        {
            auto n = j.get<int_fast64_t>();
            CHECK(json(n) == j);
        }

        SECTION("int8_least_t")
        {
            auto n = j.get<int_least8_t>();
            CHECK(json(n) == j);
        }

        SECTION("int16_least_t")
        {
            auto n = j.get<int_least16_t>();
            CHECK(json(n) == j);
        }

        SECTION("int32_least_t")
        {
            auto n = j.get<int_least32_t>();
            CHECK(json(n) == j);
        }

        SECTION("int64_least_t")
        {
            auto n = j.get<int_least64_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint8_t")
        {
            auto n = j.get<uint8_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint16_t")
        {
            auto n = j.get<uint16_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint32_t")
        {
            auto n = j.get<uint32_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint64_t")
        {
            auto n = j.get<uint64_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint8_fast_t")
        {
            auto n = j.get<uint_fast8_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint16_fast_t")
        {
            auto n = j.get<uint_fast16_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint32_fast_t")
        {
            auto n = j.get<uint_fast32_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint64_fast_t")
        {
            auto n = j.get<uint_fast64_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint8_least_t")
        {
            auto n = j.get<uint_least8_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint16_least_t")
        {
            auto n = j.get<uint_least16_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint32_least_t")
        {
            auto n = j.get<uint_least32_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint64_least_t")
        {
            auto n = j.get<uint_least64_t>();
            CHECK(json(n) == j);
        }

        SECTION("exception in case of a non-number type")
        {
            CHECK_THROWS_WITH_AS(
                json(json::value_t::null).get<json::number_integer_t>(),
                "[json.exception.type_error.302] type must be number, but is null", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::object).get<json::number_integer_t>(),
                "[json.exception.type_error.302] type must be number, but is object", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::array).get<json::number_integer_t>(),
                "[json.exception.type_error.302] type must be number, but is array", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::string).get<json::number_integer_t>(),
                "[json.exception.type_error.302] type must be number, but is string", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::boolean).get<json::number_integer_t>(),
                "[json.exception.type_error.302] type must be number, but is "
                "boolean", json::type_error&);

            CHECK_NOTHROW(
                json(json::value_t::number_float).get<json::number_integer_t>());
            CHECK_NOTHROW(
                json(json::value_t::number_float).get<json::number_unsigned_t>());
        }
    }

#if JSON_USE_IMPLICIT_CONVERSIONS
    SECTION("get an integer number (implicit)")
    {
        json::number_integer_t const n_reference{42};
        json j(n_reference);
        json::number_unsigned_t const n_unsigned_reference{42u};
        json j_unsigned(n_unsigned_reference);

        SECTION("number_integer_t")
        {
            auto n = j.get<json::number_integer_t>();
            CHECK(json(n) == j);
        }

        SECTION("number_unsigned_t")
        {
            auto n = j_unsigned.get<json::number_unsigned_t>();
            CHECK(json(n) == j_unsigned);
        }

        SECTION("short")
        {
            short const n = j;
            CHECK(json(n) == j);
        }

        SECTION("unsigned short")
        {
            unsigned short const n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("int")
        {
            int const n = j;
            CHECK(json(n) == j);
        }

        SECTION("unsigned int")
        {
            unsigned int const n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("long")
        {
            long const n = j;
            CHECK(json(n) == j);
        }

        SECTION("unsigned long")
        {
            unsigned long const n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("long long")
        {
            long long const n = j;
            CHECK(json(n) == j);
        }

        SECTION("unsigned long long")
        {
            unsigned long long const n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("int8_t")
        {
            int8_t const n = j;
            CHECK(json(n) == j);
        }

        SECTION("int16_t")
        {
            int16_t const n = j;
            CHECK(json(n) == j);
        }

        SECTION("int32_t")
        {
            int32_t const n = j;
            CHECK(json(n) == j);
        }

        SECTION("int64_t")
        {
            int64_t const n = j;
            CHECK(json(n) == j);
        }

        SECTION("int8_fast_t")
        {
            int_fast8_t const n = j;
            CHECK(json(n) == j);
        }

        SECTION("int16_fast_t")
        {
            int_fast16_t const n = j;
            CHECK(json(n) == j);
        }

        SECTION("int32_fast_t")
        {
            int_fast32_t const n = j;
            CHECK(json(n) == j);
        }

        SECTION("int64_fast_t")
        {
            int_fast64_t const n = j;
            CHECK(json(n) == j);
        }

        SECTION("int8_least_t")
        {
            int_least8_t const n = j;
            CHECK(json(n) == j);
        }

        SECTION("int16_least_t")
        {
            int_least16_t const n = j;
            CHECK(json(n) == j);
        }

        SECTION("int32_least_t")
        {
            int_least32_t const n = j;
            CHECK(json(n) == j);
        }

        SECTION("int64_least_t")
        {
            int_least64_t const n = j;
            CHECK(json(n) == j);
        }

        SECTION("uint8_t")
        {
            uint8_t const n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("uint16_t")
        {
            uint16_t const n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("uint32_t")
        {
            uint32_t const n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("uint64_t")
        {
            uint64_t const n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("uint8_fast_t")
        {
            uint_fast8_t const n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("uint16_fast_t")
        {
            uint_fast16_t const n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("uint32_fast_t")
        {
            uint_fast32_t const n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("uint64_fast_t")
        {
            uint_fast64_t const n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("uint8_least_t")
        {
            uint_least8_t const n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("uint16_least_t")
        {
            uint_least16_t const n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("uint32_least_t")
        {
            uint_least32_t const n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }

        SECTION("uint64_least_t")
        {
            uint_least64_t const n = j_unsigned;
            CHECK(json(n) == j_unsigned);
        }
    }
#endif

    SECTION("get a floating-point number (explicit)")
    {
        json::number_float_t const n_reference{42.23};
        json const j(n_reference);

        SECTION("number_float_t")
        {
            auto n = j.get<json::number_float_t>();
            CHECK(json(n).m_data.m_value.number_float == Approx(j.m_data.m_value.number_float));
        }

        SECTION("float")
        {
            auto n = j.get<float>();
            CHECK(json(n).m_data.m_value.number_float == Approx(j.m_data.m_value.number_float));
        }

        SECTION("double")
        {
            auto n = j.get<double>();
            CHECK(json(n).m_data.m_value.number_float == Approx(j.m_data.m_value.number_float));
        }

        SECTION("exception in case of a non-string type")
        {
            CHECK_THROWS_WITH_AS(
                json(json::value_t::null).get<json::number_float_t>(),
                "[json.exception.type_error.302] type must be number, but is null", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::object).get<json::number_float_t>(),
                "[json.exception.type_error.302] type must be number, but is object", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::array).get<json::number_float_t>(),
                "[json.exception.type_error.302] type must be number, but is array", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::string).get<json::number_float_t>(),
                "[json.exception.type_error.302] type must be number, but is string", json::type_error&);
            CHECK_THROWS_WITH_AS(
                json(json::value_t::boolean).get<json::number_float_t>(),
                "[json.exception.type_error.302] type must be number, but is "
                "boolean", json::type_error&);

            CHECK_NOTHROW(
                json(json::value_t::number_integer).get<json::number_float_t>());
            CHECK_NOTHROW(
                json(json::value_t::number_unsigned).get<json::number_float_t>());
        }
    }

#if JSON_USE_IMPLICIT_CONVERSIONS
    SECTION("get a floating-point number (implicit)")
    {
        json::number_float_t const n_reference{42.23};
        json const j(n_reference);

        SECTION("number_float_t")
        {
            json::number_float_t const n = j;
            CHECK(json(n).m_data.m_value.number_float == Approx(j.m_data.m_value.number_float));
        }

        SECTION("float")
        {
            float const n = j;
            CHECK(json(n).m_data.m_value.number_float == Approx(j.m_data.m_value.number_float));
        }

        SECTION("double")
        {
            double const n = j;
            CHECK(json(n).m_data.m_value.number_float == Approx(j.m_data.m_value.number_float));
        }
    }
#endif

    SECTION("get a binary value (explicit)")
    {
        json::binary_t const n_reference{{1, 2, 3}};
        json j(n_reference);

        SECTION("binary_t")
        {
            json::binary_t const b = j.get<json::binary_t>();
            CHECK(*json(b).m_data.m_value.binary == *j.m_data.m_value.binary);
        }

        SECTION("get_binary()")
        {
            SECTION("non-const")
            {
                auto& b = j.get_binary();
                CHECK(*json(b).m_data.m_value.binary == *j.m_data.m_value.binary);
            }

            SECTION("non-const")
            {
                const json j_const = j; // NOLINT(performance-unnecessary-copy-initialization)
                const auto& b = j_const.get_binary();
                CHECK(*json(b).m_data.m_value.binary == *j.m_data.m_value.binary);
            }
        }

        SECTION("exception in case of a non-string type")
        {
            json j_null(json::value_t::null);
            json j_object(json::value_t::object);
            json j_array(json::value_t::array);
            json j_string(json::value_t::string);
            json j_boolean(json::value_t::boolean);
            const json j_null_const(json::value_t::null);
            const json j_object_const(json::value_t::object);
            const json j_array_const(json::value_t::array);
            const json j_string_const(json::value_t::string);
            const json j_boolean_const(json::value_t::boolean);

            CHECK_THROWS_WITH_AS(j_null.get<json::binary_t>(),
                                 "[json.exception.type_error.302] type must be binary, but is null",
                                 json::type_error&);
            CHECK_THROWS_WITH_AS(j_object.get<json::binary_t>(),
                                 "[json.exception.type_error.302] type must be binary, but is object",
                                 json::type_error&);
            CHECK_THROWS_WITH_AS(j_array.get<json::binary_t>(),
                                 "[json.exception.type_error.302] type must be binary, but is array",
                                 json::type_error&);
            CHECK_THROWS_WITH_AS(j_string.get<json::binary_t>(),
                                 "[json.exception.type_error.302] type must be binary, but is string",
                                 json::type_error&);
            CHECK_THROWS_WITH_AS(j_boolean.get<json::binary_t>(),
                                 "[json.exception.type_error.302] type must be binary, but is boolean",
                                 json::type_error&);

            CHECK_THROWS_WITH_AS(j_null_const.get<json::binary_t>(),
                                 "[json.exception.type_error.302] type must be binary, but is null",
                                 json::type_error&);
            CHECK_THROWS_WITH_AS(j_object_const.get<json::binary_t>(),
                                 "[json.exception.type_error.302] type must be binary, but is object",
                                 json::type_error&);
            CHECK_THROWS_WITH_AS(j_array_const.get<json::binary_t>(),
                                 "[json.exception.type_error.302] type must be binary, but is array",
                                 json::type_error&);
            CHECK_THROWS_WITH_AS(j_string_const.get<json::binary_t>(),
                                 "[json.exception.type_error.302] type must be binary, but is string",
                                 json::type_error&);
            CHECK_THROWS_WITH_AS(j_boolean_const.get<json::binary_t>(),
                                 "[json.exception.type_error.302] type must be binary, but is boolean",
                                 json::type_error&);

            CHECK_THROWS_WITH_AS(j_null.get_binary(),
                                 "[json.exception.type_error.302] type must be binary, but is null",
                                 json::type_error&);
            CHECK_THROWS_WITH_AS(j_object.get_binary(),
                                 "[json.exception.type_error.302] type must be binary, but is object",
                                 json::type_error&);
            CHECK_THROWS_WITH_AS(j_array.get_binary(),
                                 "[json.exception.type_error.302] type must be binary, but is array",
                                 json::type_error&);
            CHECK_THROWS_WITH_AS(j_string.get_binary(),
                                 "[json.exception.type_error.302] type must be binary, but is string",
                                 json::type_error&);
            CHECK_THROWS_WITH_AS(j_boolean.get_binary(),
                                 "[json.exception.type_error.302] type must be binary, but is boolean",
                                 json::type_error&);

            CHECK_THROWS_WITH_AS(j_null_const.get_binary(),
                                 "[json.exception.type_error.302] type must be binary, but is null",
                                 json::type_error&);
            CHECK_THROWS_WITH_AS(j_object_const.get_binary(),
                                 "[json.exception.type_error.302] type must be binary, but is object",
                                 json::type_error&);
            CHECK_THROWS_WITH_AS(j_array_const.get_binary(),
                                 "[json.exception.type_error.302] type must be binary, but is array",
                                 json::type_error&);
            CHECK_THROWS_WITH_AS(j_string_const.get_binary(),
                                 "[json.exception.type_error.302] type must be binary, but is string",
                                 json::type_error&);
            CHECK_THROWS_WITH_AS(j_boolean_const.get_binary(),
                                 "[json.exception.type_error.302] type must be binary, but is boolean",
                                 json::type_error&);
        }
    }

#if JSON_USE_IMPLICIT_CONVERSIONS
    SECTION("get a binary value (implicit)")
    {
        json::binary_t const n_reference{{1, 2, 3}};
        json const j(n_reference);

        SECTION("binary_t")
        {
            json::binary_t const b = j;
            CHECK(*json(b).m_data.m_value.binary == *j.m_data.m_value.binary);
        }
    }
#endif

#ifndef SKIP_TESTS_FOR_ENUM_SERIALIZATION
    SECTION("get an enum")
    {
        enum c_enum { value_1, value_2 }; // NOLINT(cppcoreguidelines-use-enum-class)
        enum class cpp_enum { value_1, value_2 };

        CHECK(json(value_1).get<c_enum>() == value_1);
        CHECK(json(cpp_enum::value_1).get<cpp_enum>() == cpp_enum::value_1);
    }
#endif

    SECTION("more involved conversions")
    {
        SECTION("object-like STL containers")
        {
            json const j1 = {{"one", 1}, {"two", 2}, {"three", 3}};
            json const j2 = {{"one", 1u}, {"two", 2u}, {"three", 3u}};
            json const j3 = {{"one", 1.1}, {"two", 2.2}, {"three", 3.3}};
            json const j4 = {{"one", true}, {"two", false}, {"three", true}};
            json const j5 = {{"one", "eins"}, {"two", "zwei"}, {"three", "drei"}};

            SECTION("std::map")
            {
                j1.get<std::map<std::string, int>>();
                j2.get<std::map<std::string, unsigned int>>();
                j3.get<std::map<std::string, double>>();
                j4.get<std::map<std::string, bool>>();
                j5.get<std::map<std::string, std::string>>();
            }

            SECTION("std::unordered_map")
            {
                j1.get<std::unordered_map<std::string, int>>();
                j2.get<std::unordered_map<std::string, unsigned int>>();
                j3.get<std::unordered_map<std::string, double>>();
                j4.get<std::unordered_map<std::string, bool>>();
                j5.get<std::unordered_map<std::string, std::string>>();
                // CHECK(m5["one"] == "eins");
            }

            SECTION("std::multimap")
            {
                j1.get<std::multimap<std::string, int>>();
                j2.get<std::multimap<std::string, unsigned int>>();
                j3.get<std::multimap<std::string, double>>();
                j4.get<std::multimap<std::string, bool>>();
                j5.get<std::multimap<std::string, std::string>>();
                // CHECK(m5["one"] == "eins");
            }

            SECTION("std::unordered_multimap")
            {
                j1.get<std::unordered_multimap<std::string, int>>();
                j2.get<std::unordered_multimap<std::string, unsigned int>>();
                j3.get<std::unordered_multimap<std::string, double>>();
                j4.get<std::unordered_multimap<std::string, bool>>();
                j5.get<std::unordered_multimap<std::string, std::string>>();
                // CHECK(m5["one"] == "eins");
            }

            SECTION("exception in case of a non-object type")
            {
                CHECK_THROWS_WITH_AS(
                    (json().get<std::map<std::string, int>>()),
                    "[json.exception.type_error.302] type must be object, but is null", json::type_error&);
            }
        }

        SECTION("array-like STL containers")
        {
            json const j1 = {1, 2, 3, 4};
            json const j2 = {1u, 2u, 3u, 4u};
            json const j3 = {1.2, 2.3, 3.4, 4.5};
            json const j4 = {true, false, true};
            json const j5 = {"one", "two", "three"};

            SECTION("std::list")
            {
                j1.get<std::list<int>>();
                j2.get<std::list<unsigned int>>();
                j3.get<std::list<double>>();
                j4.get<std::list<bool>>();
                j5.get<std::list<std::string>>();
            }

            SECTION("std::forward_list")
            {
                j1.get<std::forward_list<int>>();
                j2.get<std::forward_list<unsigned int>>();
                j3.get<std::forward_list<double>>();
                j4.get<std::forward_list<bool>>();
                j5.get<std::forward_list<std::string>>();
            }

            SECTION("std::array")
            {
                j1.get<std::array<int, 4>>();
                j2.get<std::array<unsigned int, 3>>();
                j3.get<std::array<double, 4>>();
                j4.get<std::array<bool, 3>>();
                j5.get<std::array<std::string, 3>>();

                SECTION("std::array is larger than JSON")
                {
                    std::array<int, 6> arr6 = {{1, 2, 3, 4, 5, 6}};
                    CHECK_THROWS_WITH_AS(j1.get_to(arr6), "[json.exception.out_of_range.401] "
                                         "array index 4 is out of range", json::out_of_range&);
                }

                SECTION("std::array is smaller than JSON")
                {
                    std::array<int, 2> arr2 = {{8, 9}};
                    j1.get_to(arr2);
                    CHECK(arr2[0] == 1);
                    CHECK(arr2[1] == 2);
                }
            }

            SECTION("std::valarray")
            {
                j1.get<std::valarray<int>>();
                j2.get<std::valarray<unsigned int>>();
                j3.get<std::valarray<double>>();
                j4.get<std::valarray<bool>>();
                j5.get<std::valarray<std::string>>();
            }

            SECTION("std::vector")
            {
                j1.get<std::vector<int>>();
                j2.get<std::vector<unsigned int>>();
                j3.get<std::vector<double>>();
                j4.get<std::vector<bool>>();
                j5.get<std::vector<std::string>>();
            }

            SECTION("std::deque")
            {
                j1.get<std::deque<int>>();
                j2.get<std::deque<unsigned int>>();
                j2.get<std::deque<double>>();
                j4.get<std::deque<bool>>();
                j5.get<std::deque<std::string>>();
            }

            SECTION("std::set")
            {
                j1.get<std::set<int>>();
                j2.get<std::set<unsigned int>>();
                j3.get<std::set<double>>();
                j4.get<std::set<bool>>();
                j5.get<std::set<std::string>>();
            }

            SECTION("std::unordered_set")
            {
                j1.get<std::unordered_set<int>>();
                j2.get<std::unordered_set<unsigned int>>();
                j3.get<std::unordered_set<double>>();
                j4.get<std::unordered_set<bool>>();
                j5.get<std::unordered_set<std::string>>();
            }

            SECTION("std::map (array of pairs)")
            {
                const std::map<int, int> m{{0, 1}, {1, 2}, {2, 3}};
                json const j6 = m;

                auto m2 = j6.get<std::map<int, int>>();
                CHECK(m == m2);

                json const j7 = {0, 1, 2, 3};
                json const j8 = 2;
                CHECK_THROWS_WITH_AS((j7.get<std::map<int, int>>()),
                                     "[json.exception.type_error.302] type must be array, "
                                     "but is number", json::type_error&);
                CHECK_THROWS_WITH_AS((j8.get<std::map<int, int>>()),
                                     "[json.exception.type_error.302] type must be array, "
                                     "but is number", json::type_error&);

                SECTION("superfluous entries")
                {
                    json const j9 = {{0, 1, 2}, {1, 2, 3}, {2, 3, 4}};
                    m2 = j9.get<std::map<int, int>>();
                    CHECK(m == m2);
                }
            }

            SECTION("std::unordered_map (array of pairs)")
            {
                const std::unordered_map<int, int> m{{0, 1}, {1, 2}, {2, 3}};
                json const j6 = m;

                auto m2 = j6.get<std::unordered_map<int, int>>();
                CHECK(m == m2);

                json const j7 = {0, 1, 2, 3};
                json const j8 = 2;
                CHECK_THROWS_WITH_AS((j7.get<std::unordered_map<int, int>>()),
                                     "[json.exception.type_error.302] type must be array, "
                                     "but is number", json::type_error&);
                CHECK_THROWS_WITH_AS((j8.get<std::unordered_map<int, int>>()),
                                     "[json.exception.type_error.302] type must be array, "
                                     "but is number", json::type_error&);

                SECTION("superfluous entries")
                {
                    json const j9{{0, 1, 2}, {1, 2, 3}, {2, 3, 4}};
                    m2 = j9.get<std::unordered_map<int, int>>();
                    CHECK(m == m2);
                }
            }

            SECTION("exception in case of a non-object type")
            {
                // does type really must be an array? or it rather must not be null?
                // that's what I thought when other test like this one broke
                CHECK_THROWS_WITH_AS(
                    (json().get<std::list<int>>()),
                    "[json.exception.type_error.302] type must be array, but is null", json::type_error&);
                CHECK_THROWS_WITH_AS(
                    (json().get<std::vector<int>>()),
                    "[json.exception.type_error.302] type must be array, but is null", json::type_error&);
                CHECK_THROWS_WITH_AS(
                    (json().get<std::vector<json>>()),
                    "[json.exception.type_error.302] type must be array, but is null", json::type_error&);
                CHECK_THROWS_WITH_AS(
                    (json().get<std::list<json>>()),
                    "[json.exception.type_error.302] type must be array, but is null", json::type_error&);
                CHECK_THROWS_WITH_AS(
                    (json().get<std::valarray<int>>()),
                    "[json.exception.type_error.302] type must be array, but is null", json::type_error&);
                CHECK_THROWS_WITH_AS(
                    (json().get<std::map<int, int>>()),
                    "[json.exception.type_error.302] type must be array, but is null", json::type_error&);
            }
        }
    }
}

enum class cards {kreuz, pik, herz, karo};

// NOLINTNEXTLINE(misc-use-internal-linkage,misc-const-correctness,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays) - false positive
NLOHMANN_JSON_SERIALIZE_ENUM(cards,
{
    {cards::kreuz, "kreuz"},
    {cards::pik, "pik"},
    {cards::pik, "puk"},  // second entry for cards::puk; will not be used
    {cards::herz, "herz"},
    {cards::karo, "karo"}
})

enum TaskState // NOLINT(cert-int09-c,readability-enum-initial-value,cppcoreguidelines-use-enum-class)
{
    TS_STOPPED,
    TS_RUNNING,
    TS_COMPLETED,
    TS_INVALID = -1,
};

// NOLINTNEXTLINE(misc-const-correctness,misc-use-internal-linkage,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays) - false positive
NLOHMANN_JSON_SERIALIZE_ENUM(TaskState,
{
    {TS_INVALID, nullptr},
    {TS_STOPPED, "stopped"},
    {TS_RUNNING, "running"},
    {TS_COMPLETED, "completed"},
})

TEST_CASE("JSON to enum mapping")
{
    SECTION("enum class")
    {
        // enum -> json
        CHECK(json(cards::kreuz) == "kreuz");
        CHECK(json(cards::pik) == "pik");
        CHECK(json(cards::herz) == "herz");
        CHECK(json(cards::karo) == "karo");

        // json -> enum
        CHECK(cards::kreuz == json("kreuz"));
        CHECK(cards::pik == json("pik"));
        CHECK(cards::herz == json("herz"));
        CHECK(cards::karo == json("karo"));

        // invalid json -> first enum
        CHECK(cards::kreuz == json("what?").get<cards>());
    }

    SECTION("traditional enum")
    {
        // enum -> json
        CHECK(json(TS_STOPPED) == "stopped");
        CHECK(json(TS_RUNNING) == "running");
        CHECK(json(TS_COMPLETED) == "completed");
        CHECK(json(TS_INVALID) == json());

        // json -> enum
        CHECK(TS_STOPPED == json("stopped"));
        CHECK(TS_RUNNING == json("running"));
        CHECK(TS_COMPLETED == json("completed"));
        CHECK(TS_INVALID == json());

        // invalid json -> first enum
        CHECK(TS_INVALID == json("what?").get<TaskState>());
    }
}

#ifdef JSON_HAS_CPP_17
#if JSON_HAS_FILESYSTEM || JSON_HAS_EXPERIMENTAL_FILESYSTEM
TEST_CASE("std::filesystem::path")
{
    SECTION("ascii")
    {
        json const j_string = "Path";
        auto p = j_string.template get<nlohmann::detail::std_fs::path>();
        json const j_path = p;

        CHECK(j_path.template get<std::string>() ==
              j_string.template get<std::string>());
    }

    SECTION("utf-8")
    {
        json const j_string = "P\xc4\x9b\xc5\xa1ina";
        auto p = j_string.template get<nlohmann::detail::std_fs::path>();
        json const j_path = p;

        CHECK(j_path.template get<std::string>() ==
              j_string.template get<std::string>());
    }
}
#endif

#ifndef JSON_USE_IMPLICIT_CONVERSIONS
TEST_CASE("std::optional")
{
    SECTION("null")
    {
        json j_null;
        std::optional<std::string> opt_null;

        CHECK(json(opt_null) == j_null);
        CHECK(j_null.get<std::optional<std::string>>() == std::nullopt);
    }

    SECTION("string")
    {
        json j_string = "string";
        std::optional<std::string> opt_string = "string";

        CHECK(json(opt_string) == j_string);
        CHECK(std::optional<std::string>(j_string) == opt_string);
    }

    SECTION("bool")
    {
        json j_bool = true;
        std::optional<bool> opt_bool = true;

        CHECK(json(opt_bool) == j_bool);
        CHECK(std::optional<bool>(j_bool) == opt_bool);
    }

    SECTION("number")
    {
        json j_number = 1;
        std::optional<int> opt_int = 1;

        CHECK(json(opt_int) == j_number);
        CHECK(j_number.get<std::optional<int>>() == opt_int);
    }

    SECTION("array")
    {
        json j_array = {1, 2, nullptr};
        std::vector<std::optional<int>> opt_array = {{1, 2, std::nullopt}};

        CHECK(json(opt_array) == j_array);
        CHECK(j_array.get<std::vector<std::optional<int>>>() == opt_array);
    }

    SECTION("object")
    {
        json j_object = {{"one", 1}, {"two", 2}, {"zero", nullptr}};
        std::map<std::string, std::optional<int>> opt_object {{"one", 1}, {"two", 2}, {"zero", std::nullopt}};

        CHECK(json(opt_object) == j_object);
        CHECK(std::map<std::string, std::optional<int>>(j_object) == opt_object);
    }
}
#endif
#endif

#ifdef JSON_HAS_CPP_17
    #undef JSON_HAS_CPP_17
#endif

#ifdef JSON_HAS_CPP_14
    #undef JSON_HAS_CPP_14
#endif
DOCTEST_CLANG_SUPPRESS_WARNING_POP
