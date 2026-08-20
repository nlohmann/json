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

// This file continues unit-regression2.cpp, which the MinGW linker cannot
// relocate once it grows past a certain size ("relocation truncated to fit").
// Keep it building for the same standards as that file:
// JSON_HAS_CPP_17 (do not remove; see note at top of file)
// JSON_HAS_CPP_20 (do not remove; see note at top of file)

#include "doctest_compatibility.h"

#define JSON_TESTS_PRIVATE
#include <nlohmann/json.hpp>
using json = nlohmann::json;
using ordered_json = nlohmann::ordered_json;

#include <cmath>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

TEST_CASE_TEMPLATE("issue #4798 - nlohmann::json::to_msgpack() encode float NaN as double", T, double, float) // NOLINT(readability-math-missing-parentheses, bugprone-throwing-static-initialization)
{
    // With issue #4798, we encode NaN, infinity, and -infinity as float instead
    // of double to allow for smaller encodings.
    const json jx = std::numeric_limits<T>::quiet_NaN();
    const json jy = std::numeric_limits<T>::infinity();
    const json jz = -std::numeric_limits<T>::infinity();

    /////////////////////////////////////////////////////////////////////////
    // MessagePack
    /////////////////////////////////////////////////////////////////////////

    // expected MessagePack values
    const std::vector<std::uint8_t> msgpack_x = {{0xCA, 0x7F, 0xC0, 0x00, 0x00}};
    const std::vector<std::uint8_t> msgpack_y = {{0xCA, 0x7F, 0x80, 0x00, 0x00}};
    const std::vector<std::uint8_t> msgpack_z = {{0xCA, 0xFF, 0x80, 0x00, 0x00}};

    CHECK(json::to_msgpack(jx) == msgpack_x);
    CHECK(json::to_msgpack(jy) == msgpack_y);
    CHECK(json::to_msgpack(jz) == msgpack_z);

    CHECK(std::isnan(json::from_msgpack(msgpack_x).get<T>()));
    CHECK(json::from_msgpack(msgpack_y).get<T>() == std::numeric_limits<T>::infinity());
    CHECK(json::from_msgpack(msgpack_z).get<T>() == -std::numeric_limits<T>::infinity());

    // Make sure the other MessagePakc encodings for NaN, infinity, and
    // -infinity are still supported.
    const std::vector<std::uint8_t> msgpack_x_2 = {{0xCB, 0x7F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
    const std::vector<std::uint8_t> msgpack_y_2 = {{0xCB, 0x7F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
    const std::vector<std::uint8_t> msgpack_z_2 = {{0xCB, 0xFF, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
    CHECK(std::isnan(json::from_msgpack(msgpack_x_2).get<T>()));
    CHECK(json::from_msgpack(msgpack_y_2).get<T>() == std::numeric_limits<T>::infinity());
    CHECK(json::from_msgpack(msgpack_z_2).get<T>() == -std::numeric_limits<T>::infinity());

    /////////////////////////////////////////////////////////////////////////
    // CBOR
    /////////////////////////////////////////////////////////////////////////

    // expected CBOR values
    const std::vector<std::uint8_t> cbor_x = {{0xF9, 0x7E, 0x00}};
    const std::vector<std::uint8_t> cbor_y = {{0xF9, 0x7C, 0x00}};
    const std::vector<std::uint8_t> cbor_z = {{0xF9, 0xfC, 0x00}};

    CHECK(json::to_cbor(jx) == cbor_x);
    CHECK(json::to_cbor(jy) == cbor_y);
    CHECK(json::to_cbor(jz) == cbor_z);

    CHECK(std::isnan(json::from_cbor(cbor_x).get<T>()));
    CHECK(json::from_cbor(cbor_y).get<T>() == std::numeric_limits<T>::infinity());
    CHECK(json::from_cbor(cbor_z).get<T>() == -std::numeric_limits<T>::infinity());

    // Make sure the other CBOR encodings for NaN, infinity, and -infinity are
    // still supported.
    const std::vector<std::uint8_t> cbor_x_2 = {{0xFA, 0x7F, 0xC0, 0x00, 0x00}};
    const std::vector<std::uint8_t> cbor_y_2 = {{0xFA, 0x7F, 0x80, 0x00, 0x00}};
    const std::vector<std::uint8_t> cbor_z_2 = {{0xFA, 0xFF, 0x80, 0x00, 0x00}};
    const std::vector<std::uint8_t> cbor_x_3 = {{0xFB, 0x7F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
    const std::vector<std::uint8_t> cbor_y_3 = {{0xFB, 0x7F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
    const std::vector<std::uint8_t> cbor_z_3 = {{0xFB, 0xFF, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
    CHECK(std::isnan(json::from_cbor(cbor_x_2).get<T>()));
    CHECK(json::from_cbor(cbor_y_2).get<T>() == std::numeric_limits<T>::infinity());
    CHECK(json::from_cbor(cbor_z_2).get<T>() == -std::numeric_limits<T>::infinity());
    CHECK(std::isnan(json::from_cbor(cbor_x_3).get<T>()));
    CHECK(json::from_cbor(cbor_y_3).get<T>() == std::numeric_limits<T>::infinity());
    CHECK(json::from_cbor(cbor_z_3).get<T>() == -std::numeric_limits<T>::infinity());
}

TEST_CASE("regression test #5074 - portable workaround for single-element brace init")
{
    json const j_obj = {{"key", "value"}};

    json const j = json::array({j_obj});
    CHECK(j.is_array());
    CHECK(j.size() == 1);
    CHECK(j[0] == j_obj);
}

#if defined(JSON_BRACE_INIT_COPY_SEMANTICS) && (JSON_BRACE_INIT_COPY_SEMANTICS == 1)
TEST_CASE("regression test #5074 - single-element brace init with JSON_BRACE_INIT_COPY_SEMANTICS")
{
    // with JSON_BRACE_INIT_COPY_SEMANTICS: single-element brace init copies/moves
    json const j_obj = {{"key", "value"}, {"num", 42}};
    json const j_arr = {1, 2, 3};

    // object: brace init copies instead of wrapping
    json const j1{j_obj};
    CHECK(j1.is_object());
    CHECK(j1 == j_obj);

    // array: brace init copies instead of wrapping
    json const j2{j_arr};
    CHECK(j2.is_array());
    CHECK(j2.size() == 3);
    CHECK(j2 == j_arr);

    // primitives still work as initializer lists
    json const j3{true};
    CHECK(j3.is_boolean());

    json const j4{42};
    CHECK(j4.is_number_integer());
}
#endif

struct Example_5122
{
    float b = 2;
    nlohmann::ordered_map<std::string, std::string> c{}; // NOLINT(readability-redundant-member-init): needed for GCC -Weffc++
    int a = 1;
    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(Example_5122, b, c, a)
};

TEST_CASE("regression test #5122 - from_json into types holding nlohmann::ordered_map")
{
    Example_5122 src;
    src.c.emplace("first", "1");
    src.c.emplace("second", "2");

    ordered_json const j = src;
    Example_5122 const dst = j.get<Example_5122>();

    CHECK(dst.b == src.b);
    CHECK(dst.a == src.a);
    REQUIRE(dst.c.size() == src.c.size());
    auto src_it = src.c.begin();
    auto dst_it = dst.c.begin();
    for (; src_it != src.c.end(); ++src_it, ++dst_it)
    {
        CHECK(dst_it->first == src_it->first);
        CHECK(dst_it->second == src_it->second);
    }
}

// -Wself-assign-overloaded was introduced in Clang 7. Gate the pragma on
// __has_warning so older Clang versions do not error with "unknown warning
// group". The __has_warning check has to stay inside the __clang__ branch
// because GCC does not provide it and would tokenize-error on the argument.
#if defined(__clang__) && defined(__has_warning)
    #if __has_warning("-Wself-assign-overloaded")
        DOCTEST_CLANG_SUPPRESS_WARNING_PUSH
        DOCTEST_CLANG_SUPPRESS_WARNING("-Wself-assign-overloaded")
    #endif
#endif

TEST_CASE("regression test #5122 - nlohmann::ordered_map copy-assignment is self-assignment safe")
{
    nlohmann::ordered_map<std::string, std::string> m;
    m.emplace("first", "1");
    m.emplace("second", "2");

    // Insertion order is preserved by ordered_map, so we can check it directly.
    m = m;

    REQUIRE(m.size() == 2);
    auto it = m.begin();
    CHECK(it->first == "first");
    CHECK(it->second == "1");
    ++it;
    CHECK(it->first == "second");
    CHECK(it->second == "2");
}

#if defined(__clang__) && defined(__has_warning)
    #if __has_warning("-Wself-assign-overloaded")
        DOCTEST_CLANG_SUPPRESS_WARNING_POP
    #endif
#endif

TEST_CASE("regression test #5122 - nlohmann::ordered_map move-assignment transfers contents")
{
    nlohmann::ordered_map<std::string, std::string> src;
    src.emplace("first", "1");
    src.emplace("second", "2");

    nlohmann::ordered_map<std::string, std::string> dst;
    dst.emplace("stale", "x");
    dst = std::move(src);

    REQUIRE(dst.size() == 2);
    auto it = dst.begin();
    CHECK(it->first == "first");
    CHECK(it->second == "1");
    ++it;
    CHECK(it->first == "second");
    CHECK(it->second == "2");

    // Re-assigning into the moved-from object must leave it in a usable state.
    src = nlohmann::ordered_map<std::string, std::string> {};
    src.emplace("after-move", "3");
    REQUIRE(src.size() == 1);
    CHECK(src.begin()->first == "after-move");
}

// Stand-in for a third-party library (e.g., Eigen as of 3.4, which added
// STL-compatible begin()/end() to its vector types), living in its own
// namespace with its own to_json overload for its vector type.
namespace issue_4320_eigen
{
// "array-compatible" from the library's point of view (it has begin()/end()),
// but for which this (fake) third-party namespace provides its own to_json.
struct vector3
{
    double v[3]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,cppcoreguidelines-use-default-member-init,modernize-use-default-member-init)
    vector3(double x, double y, double z) : v{x, y, z} {} // NOLINT(hicpp-member-init,cppcoreguidelines-pro-type-member-init)
    double x() const
    {
        return v[0];
    }
    double y() const
    {
        return v[1];
    }
    double z() const
    {
        return v[2];
    }
    double* begin()
    {
        return v;
    }
    double* end()
    {
        return v + 3;
    }
    const double* begin() const
    {
        return v;
    }
    const double* end() const
    {
        return v + 3;
    }
};

inline void to_json(json& j, const vector3& v) // NOLINT(misc-use-internal-linkage)
{
    j = {{"x", v.x()}, {"y", v.y()}, {"z", v.z()}};
}
} // namespace issue_4320_eigen

// The user's own namespace, using the (fake) Eigen type as an implementation
// detail behind a payload type that has nothing to do with vectors/arrays.
namespace issue_4320
{
// Publicly derives from issue_4320_eigen::vector3 but does *not* define its
// own to_json - it is only ever used as a temporary to reach the base
// class's to_json via ADL.
struct vector3_wrapper : issue_4320_eigen::vector3
{
    using issue_4320_eigen::vector3::vector3;
};

struct payload
{
    double x, y, z;
};

inline vector3_wrapper to_eigen(const payload& p) // NOLINT(misc-use-internal-linkage)
{
    return {p.x, p.y, p.z};
}

inline void to_json(json& j, const payload& p) // NOLINT(misc-use-internal-linkage)
{
    // Unqualified call, passing a *derived* vector3_wrapper: relies on ADL
    // finding issue_4320_eigen::to_json(json&, const vector3&) through the
    // vector3 base class, via a derived-to-base conversion. Must NOT resolve
    // to the library's own generic array-compatible to_json (an exact-match
    // template for vector3_wrapper, since it also has begin()/end()), which
    // would serialize this as [x, y, z] instead of {"x":x, "y":y, "z":z}.
    to_json(j, to_eigen(p));
}
} // namespace issue_4320

TEST_CASE("issue #4320 - custom base class must not leak nlohmann::detail into ADL")
{
    // Before the fix, basic_json unconditionally derived from a type living in
    // nlohmann::detail (json_default_base), which made nlohmann::detail an
    // associated namespace of every basic_json for ADL purposes. That leaked
    // the library's internal generic-array to_json overload into unqualified
    // to_json() calls made from user code, silently bypassing user-defined
    // to_json overloads reached via a derived-to-base conversion.
    const issue_4320::payload p{1.0, 2.0, 3.0};

    json j;
    to_json(j, p);
    CHECK(j == json({{"x", 1.0}, {"y", 2.0}, {"z", 3.0}}));
}

TEST_CASE("issue #5338 - truncated CBOR tagged binary subtype is rejected")
{
    const std::vector<std::vector<std::uint8_t>> truncated_tags =
    {
        {0xD8},
        {0xD9, 0x00},
        {0xDA, 0x00, 0x00, 0x00},
        {0xDB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
    };

    for (const auto& data : truncated_tags)
    {
        CAPTURE(data);
        for (const auto tag_handler :
                {
                    json::cbor_tag_handler_t::ignore, json::cbor_tag_handler_t::store
                })
        {
            CAPTURE(tag_handler);
            const auto result = json::from_cbor(data, true, false, tag_handler);
            CHECK(result.is_discarded());
        }
    }
}

TEST_CASE("issue #5402 - update(merge_objects=true) overwrites a primitive with an object")
{
    json t = {{"k", 1}};
    t.update(json{{"k", {{"x", 2}}}}, true);
    CHECK(t == json({{"k", {{"x", 2}}}}));

    json mixed = {{"keep", {{"a", 1}}}, {"replace", 1}};
    mixed.update(json{{"keep", {{"b", 2}}}, {"replace", {{"x", 2}}}}, true);
    CHECK(mixed == json({{"keep", {{"a", 1}, {"b", 2}}}, {"replace", {{"x", 2}}}}));
}
