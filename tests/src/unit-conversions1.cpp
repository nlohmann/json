//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// cmake/test.cmake selects the C++ standard versions with which to build a
// unit test based on the presence of JSON_HAS_CPP_<VERSION> macros.
// When using macros that are only defined for particular versions of the standard
// (e.g., JSON_HAS_FILESYSTEM for C++17 and up), please mention the corresponding
// version macro in a comment close by, like this:
// JSON_HAS_CPP_<VERSION> (do not remove; see note at top of file)

#include "doctest_compatibility.h"

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

        SECTION("built-in arrays: 5D")
        {
            // NOLINTBEGIN(misc-const-correctness,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
            const int nbs[1][1][1][2][2] = {{{{{0, 1}, {2, 3}}}}};
            int nbs2[1][1][1][2][2] = {{{{{0, 0}, {0, 0}}}}};
            // NOLINTEND(misc-const-correctness,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)

            const json j2 = nbs;
            j2.get_to(nbs2);
            CHECK(std::equal(std::begin(nbs[0][0][0][0]), std::end(nbs[0][0][0][1]), std::begin(nbs2[0][0][0][0])));
        }

        SECTION("built-in arrays: mismatched shape")
        {
            // NOLINTBEGIN(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
            int nbs2[2][3] = {{0, 0, 0}, {0, 0, 0}};
            // NOLINTEND(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)

            SECTION("not an array")
            {
                const json j2 = 42;
                CHECK_THROWS_WITH_AS(j2.get_to(nbs2), "[json.exception.type_error.304] cannot use at() with number", json::type_error&);
            }

            SECTION("too few elements")
            {
                const json j2 = {{0, 1, 2}};
                CHECK_THROWS_WITH_AS(j2.get_to(nbs2), "[json.exception.out_of_range.401] array index 1 is out of range", json::out_of_range&);
            }
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
}

#ifdef JSON_HAS_CPP_17
    #undef JSON_HAS_CPP_17
#endif

#ifdef JSON_HAS_CPP_14
    #undef JSON_HAS_CPP_14
#endif
DOCTEST_CLANG_SUPPRESS_WARNING_POP
