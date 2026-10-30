//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json_view.hpp>
using nlohmann::json;
using nlohmann::json_document;
using nlohmann::json_view;
using nlohmann::json_editable_document;
using nlohmann::ordered_json_document;

#include "json_view_test_helpers.hpp"
#if !defined(JSON_NOEXCEPTION)
    using json_view_test::exception_of_call;
#endif

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <forward_list>
#include <list>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <valarray>
#include <vector>

#ifdef JSON_HAS_CPP_17
    #include <optional>
#endif

// NLOHMANN_JSON_SERIALIZE_ENUM uses a static std::pair; same() compares floating-point values on purpose
DOCTEST_CLANG_SUPPRESS_WARNING_PUSH
DOCTEST_CLANG_SUPPRESS_WARNING("-Wexit-time-destructors")
DOCTEST_CLANG_SUPPRESS_WARNING("-Wfloat-equal")
DOCTEST_GCC_SUPPRESS_WARNING_PUSH
DOCTEST_GCC_SUPPRESS_WARNING("-Wfloat-equal")

// The from_json() functions of the NLOHMANN_DEFINE_TYPE_* and
// NLOHMANN_JSON_SERIALIZE_ENUM macros read views directly; other from_json()
// functions get the value of materialize().

namespace view_from_json
{
struct point
{
    int x = 0;
    int y = 0;
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(point, x, y)

    friend bool operator==(const point& a, const point& b)
    {
        return a.x == b.x && a.y == b.y;
    }
};

struct shape
{
    // initialized for GCC -Weffc++
    // NOLINTNEXTLINE(readability-redundant-member-init)
    std::string name{};
    // NOLINTNEXTLINE(readability-redundant-member-init)
    std::vector<point> points{};
    point center{};
    // NOLINTNEXTLINE(readability-redundant-member-init)
    std::map<std::string, point> named{};
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(shape, name, points, center, named)
};

struct with_defaults
{
    int a = 1;
    std::string b = "default";
    std::vector<int> c = {1, 2};
};
// NOLINTNEXTLINE(misc-use-internal-linkage): found by ADL, like the from_json() functions of users
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(with_defaults, a, b, c)

struct with_names
{
    int value = 0;
    // initialized for GCC -Weffc++
    // NOLINTNEXTLINE(readability-redundant-member-init)
    std::string text{};
};
// NOLINTNEXTLINE(misc-use-internal-linkage): found by ADL, like the from_json() functions of users
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_NAMES(with_names, "Value", value, "Text", text)

struct empty
{
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(empty)
};

enum class color
{
    red,
    green,
    blue
};
// NOLINTNEXTLINE(misc-use-internal-linkage): found by ADL, like the from_json() functions of users
NLOHMANN_JSON_SERIALIZE_ENUM(color,
{
    {color::red, "red"},
    {color::green, "green"},
    {color::blue, nullptr},
})

enum class strict_color
{
    red,
    green
};
// NOLINTNEXTLINE(misc-use-internal-linkage): found by ADL, like the from_json() functions of users
NLOHMANN_JSON_SERIALIZE_ENUM_STRICT(strict_color,
{
    {strict_color::red, "red"},
    {strict_color::green, 1},
})

struct base
{
    int id = 0;
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(base, id)
};

struct derived : base
{
    color c = color::red;
    NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE(derived, base, c)
};

struct derived_with_defaults : base
{
    std::string label = "none";
    NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_DEFAULT(derived_with_defaults, base, label)
};

// a base whose from_json() is written for json only: the derived type reads
// its own members from the view and the base part from materialize()
struct legacy_base
{
    int id = 0;
};
// NOLINTNEXTLINE(misc-use-internal-linkage): found by ADL, like the from_json() functions of users
inline void from_json(const json& j, legacy_base& b)
{
    b.id = j.at("id").get<int>();
}

struct derived_from_legacy : legacy_base
{
    int extra = 0;
};
// NOLINTNEXTLINE(misc-use-internal-linkage): found by ADL, like the from_json() functions of users
NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE(derived_from_legacy, legacy_base, extra)

// from_json() for json only: converted through materialize()
struct legacy
{
    int v = 0;
};
// NOLINTNEXTLINE(misc-use-internal-linkage): found by ADL, like the from_json() functions of users
inline void from_json(const json& j, legacy& l)
{
    l.v = j.at("v").get<int>();
}

// an unconstrained from_json() template, as in the documentation of
// arbitrary type conversions: converted through materialize()
struct unconstrained
{
    int v = 0;
};
template<typename BasicJsonType>
// NOLINTNEXTLINE(misc-use-internal-linkage): found by ADL, like the from_json() functions of users
void from_json(const BasicJsonType& j, unconstrained& u)
{
    u.v = j.at("v").template get<int>();
}

// a from_json() constrained by the user to views and json: reads the view
struct constrained
{
    int v = 0;
};
template < typename J, typename std::enable_if < nlohmann::is_json_view<J>::value || std::is_same<J, json>::value, int >::type = 0 >
// NOLINTNEXTLINE(misc-use-internal-linkage): found by ADL, like the from_json() functions of users
void from_json(const J& j, constrained& c)
{
    c.v = j.at("v").template get<int>();
}
}  // namespace view_from_json

namespace
{
template<typename T, typename View = json_view>
struct reads_view : nlohmann::detail::has_view_from_json<nlohmann::adl_serializer<T, void>, View, T> {};

// whether a member converts to the same T from the view and from the materialized value
template<typename T>
bool same(const json_view& v, const json& j, const char* key)
{
    return v[key].get<T>() == j[key].get<T>();
}
}  // namespace

TEST_CASE("json_view from_json")
{
    using namespace view_from_json; // NOLINT(google-build-using-namespace)

    SECTION("which from_json() functions read views")
    {
        static_assert(reads_view<point>::value, "macro types read views");
        static_assert(reads_view<shape>::value, "macro types read views");
        static_assert(reads_view<with_defaults>::value, "macro types read views");
        static_assert(reads_view<with_names>::value, "macro types read views");
        static_assert(reads_view<empty>::value, "macro types read views");
        static_assert(reads_view<derived>::value, "macro types read views");
        static_assert(reads_view<derived_from_legacy>::value, "macro types read views");
        static_assert(reads_view<color>::value, "enum macro types read views");
        static_assert(reads_view<strict_color>::value, "enum macro types read views");
        static_assert(reads_view<constrained>::value, "constrained from_json() reads views");
        static_assert(reads_view<point, nlohmann::json_editable_view>::value, "editable views as well");
        static_assert(reads_view<point, nlohmann::ordered_json_view>::value, "views of ordered_json as well");
        static_assert(!reads_view<legacy>::value, "from_json() for json");
        static_assert(!reads_view<legacy_base>::value, "from_json() for json");
        static_assert(!reads_view<unconstrained>::value, "unconstrained from_json()");

        static_assert(nlohmann::is_json_view<json_view>::value, "is_json_view");
        static_assert(nlohmann::is_json_view<nlohmann::ordered_json_editable_view>::value, "is_json_view");
        static_assert(!nlohmann::is_json_view<json>::value, "is_json_view");
        static_assert(!nlohmann::is_json_view<json_document>::value, "is_json_view");
        static_assert(!nlohmann::is_json_view<int>::value, "is_json_view");
    }

    SECTION("the library's own conversions read views")
    {
        static_assert(reads_view<std::list<int>>::value, "std types");
        static_assert(reads_view<std::deque<point>>::value, "std types");
        static_assert(reads_view<std::set<std::string>>::value, "std types");
        static_assert(reads_view<std::unordered_set<int>>::value, "std types");
        static_assert(reads_view<std::forward_list<int>>::value, "std types");
        static_assert(reads_view<std::valarray<double>>::value, "std types");
        static_assert(reads_view<std::array<int, 3>>::value, "std types");
        static_assert(reads_view<std::pair<int, std::string>>::value, "std types");
        static_assert(reads_view<std::tuple<int, bool, point>>::value, "std types");
        static_assert(reads_view<std::map<int, int>>::value, "std types");
        static_assert(reads_view<std::unordered_map<int, point>>::value, "std types");
        static_assert(reads_view<std::map<color, int>>::value, "std types");
        static_assert(reads_view<std::map<std::string, int>>::value, "std types");
        static_assert(reads_view<std::vector<point>>::value, "std types");
        static_assert(reads_view<std::vector<bool>>::value, "std types");
        static_assert(reads_view<std::vector<std::uint8_t>>::value, "std types");
        static_assert(reads_view<std::string>::value, "std types");
        static_assert(reads_view<int>::value, "std types");
        static_assert(reads_view<bool>::value, "std types");
        static_assert(reads_view<double>::value, "std types");
        static_assert(reads_view<std::nullptr_t>::value, "std types");
        static_assert(!reads_view<json>::value, "get<BasicJsonType>() is materialize()");
        static_assert(reads_view<json::binary_t>::value, "std types");
#ifdef JSON_HAS_CPP_17
        static_assert(reads_view<std::optional<point>>::value, "std types");
#endif
        CHECK(true);
    }

    SECTION("std types: the same values as from the materialized value")
    {
        const json_document d = json_document::parse(R"({"ints": [3, 1, 2, 1], "strings": ["b", "a", "b"], "pairs": [[1, "x"], [2, "y"]],
            "points": [{"x": 1, "y": 2}, {"x": 3, "y": 4}], "object": {"b": 1, "a": 2}, "triple": [1, true, {"x": 5, "y": 6}],
            "colors": {"green": 1, "red": 2}, "bytes": [1, 2, 255], "nested": [[1, 2], [3]], "number": 1.5, "flag": true,
            "text": "hello", "nothing": null, "mixed": [1, 2.5, -3, 4], "flags": [true, false, true]})");
        const json j = d.root().materialize();
        const json_view v = d.root();
        CHECK(same<std::list<int>>(v, j, "ints"));
        CHECK(same<std::deque<int>>(v, j, "ints"));
        CHECK(same<std::set<int>>(v, j, "ints"));
        CHECK(same<std::multiset<int>>(v, j, "ints"));
        CHECK(same<std::unordered_set<std::string>>(v, j, "strings"));
        CHECK(same<std::forward_list<int>>(v, j, "ints"));
        CHECK(same<std::array<int, 4>>(v, j, "ints"));
        CHECK(same<std::array<double, 4>>(v, j, "mixed"));
        CHECK((v["pairs"][0].get<std::pair<int, std::string>>() == j["pairs"][0].get<std::pair<int, std::string>>()));
        CHECK(same<std::vector<std::pair<int, std::string>>>(v, j, "pairs"));
        CHECK(same<std::tuple<int, bool, point>>(v, j, "triple"));
        CHECK(same<std::map<int, std::string>>(v, j, "pairs"));
        CHECK(same<std::unordered_map<int, std::string>>(v, j, "pairs"));
        CHECK(same<std::map<std::string, int>>(v, j, "object"));
        CHECK(same<std::unordered_map<std::string, int>>(v, j, "object"));
        CHECK(same<std::map<color, int>>(v, j, "colors"));
        CHECK(same<std::vector<point>>(v, j, "points"));
        CHECK(same<std::vector<int>>(v, j, "ints"));
        CHECK(same<std::vector<bool>>(v, j, "flags"));
        CHECK(same<std::vector<std::uint8_t>>(v, j, "bytes"));
        CHECK(same<std::vector<std::vector<int>>>(v, j, "nested"));
        CHECK(same<std::vector<json>>(v, j, "mixed"));
        CHECK(same<double>(v, j, "number"));
        CHECK(same<bool>(v, j, "flag"));
        CHECK(same<std::string>(v, j, "text"));
        CHECK(same<std::nullptr_t>(v, j, "nothing"));
        CHECK(same<json>(v, j, "object"));
        const auto va = v["ints"].get<std::valarray<int>>();
        CHECK(va.size() == 4);
        CHECK(va[0] == 3);
        int c_array[2][2] = {{0, 0}, {0, 0}}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays): the conversion to C arrays
        v["nested"][0].get_to(c_array[0]);
        CHECK(c_array[0][1] == 2);
#ifdef JSON_HAS_CPP_17
        const auto first = v["points"][0].get<std::optional<point>>();
        CHECK((first.has_value() && first->y == 2));
        CHECK(!v["nothing"].get<std::optional<point>>().has_value());
#endif
        // containers of views keep views of the elements
        const auto views = v["points"].get<std::vector<json_view>>();
        CHECK(views.size() == 2);
        CHECK(views[1]["x"].get<int>() == 3);
        CHECK(v["object"].get<std::map<std::string, json_view>>().at("a").get<int>() == 2);
    }

    SECTION("std types: duplicate keys keep the last value, as from the materialized value")
    {
        const json_document d = json_document::parse(R"({"a": 1, "b": 2, "a": 3})");
        CHECK((d.root().get<std::map<std::string, int>>() == d.root().materialize().get<std::map<std::string, int>>()));
        CHECK(d.root().get<std::map<std::string, int>>().at("a") == 3);
        CHECK(d.root().get<std::unordered_map<std::string, int>>().at("a") == 3);
    }

#if !defined(JSON_NOEXCEPTION)
    SECTION("std types: the same errors as from the materialized value")
    {
        const json_document d = json_document::parse(R"([[1, "x"], {"a": 1}, "text", [1], 5, null])");
        const json j = d.root().materialize();
        for (std::size_t i = 0; i < 6; ++i)
        {
            CAPTURE(i)
            const json_view v = d.root()[i];
            CHECK(exception_of_call([&] { static_cast<void>(v.get<std::list<int>>()); }) == exception_of_call([&] { static_cast<void>(j[i].get<std::list<int>>()); }));
            CHECK(exception_of_call([&] { static_cast<void>(v.get<std::forward_list<int>>()); }) == exception_of_call([&] { static_cast<void>(j[i].get<std::forward_list<int>>()); }));
            CHECK(exception_of_call([&] { static_cast<void>(v.get<std::array<int, 2>>()); }) == exception_of_call([&] { static_cast<void>(j[i].get<std::array<int, 2>>()); }));
            CHECK(exception_of_call([&] { static_cast<void>(v.get<std::pair<int, std::string>>()); }) == exception_of_call([&] { static_cast<void>(j[i].get<std::pair<int, std::string>>()); }));
            CHECK(exception_of_call([&] { static_cast<void>(v.get<std::map<std::string, int>>()); }) == exception_of_call([&] { static_cast<void>(j[i].get<std::map<std::string, int>>()); }));
            CHECK(exception_of_call([&] { static_cast<void>(v.get<std::map<int, int>>()); }) == exception_of_call([&] { static_cast<void>(j[i].get<std::map<int, int>>()); }));
            CHECK(exception_of_call([&] { static_cast<void>(v.get<std::vector<std::uint8_t>>()); }) == exception_of_call([&] { static_cast<void>(j[i].get<std::vector<std::uint8_t>>()); }));
            CHECK(exception_of_call([&] { static_cast<void>(v.get<json::binary_t>()); }) == exception_of_call([&] { static_cast<void>(j[i].get<json::binary_t>()); }));
            CHECK(exception_of_call([&] { static_cast<void>(v.get<std::valarray<int>>()); }) == exception_of_call([&] { static_cast<void>(j[i].get<std::valarray<int>>()); }));
        }
    }
#endif

    SECTION("macro types")
    {
        const json_document d = json_document::parse(R"({"name": "s", "points": [{"x": 1, "y": 2}, {"x": 3, "y": 4}],
            "center": {"x": 5, "y": 6}, "named": {"a": {"x": 7, "y": 8}}})");
        const auto s = d.root().get<shape>();
        CHECK(s.name == "s");
        CHECK(s.points.size() == 2);
        CHECK(s.points[1].y == 4);
        CHECK(s.center.x == 5);
        CHECK(s.named.at("a").y == 8);

        point p;
        d.root()["center"].get_to(p);
        CHECK(p.x == 5);
        CHECK(p.y == 6);

        static_cast<void>(d.root()["center"].get<empty>());
    }

    SECTION("defaults and names")
    {
        const json_document d = json_document::parse(R"({"a": 5, "Value": 3, "Text": "t"})");
        const auto w = d.root().get<with_defaults>();
        CHECK(w.a == 5);
        CHECK(w.b == "default");
        CHECK(w.c == std::vector<int> {1, 2});
        const json_document null_document = json_document::parse("null");
        CHECK(null_document.root().get<with_defaults>().a == 1);
        const auto n = d.root().get<with_names>();
        CHECK(n.value == 3);
        CHECK(n.text == "t");
    }

    SECTION("enums")
    {
        const json_document d = json_document::parse(R"(["green", null, "purple", 1, "red"])");
        CHECK(d.root()[0].get<color>() == color::green);
        CHECK(d.root()[1].get<color>() == color::blue);
        CHECK(d.root()[2].get<color>() == color::red); // unknown values map to the first entry
        CHECK(d.root()[3].get<strict_color>() == strict_color::green);
        CHECK(d.root()[4].get<strict_color>() == strict_color::red);
#if !defined(JSON_NOEXCEPTION)
        const json j = d.root().materialize();
#if !JSON_DIAGNOSTICS && !JSON_DIAGNOSTIC_POSITIONS
        CHECK(exception_of_call([&] { static_cast<void>(d.root()[2].get<strict_color>()); }) == "[json.exception.out_of_range.410] enum value out of range for strict_color: \"purple\"");
#endif
        CHECK(exception_of_call([&] { static_cast<void>(d.root()[2].get<strict_color>()); }) == exception_of_call([&] { static_cast<void>(j[2].get<strict_color>()); }));
#endif
    }

    SECTION("derived types")
    {
        const json_document d = json_document::parse(R"({"id": 7, "c": "green", "extra": 3})");
        const auto x = d.root().get<derived>();
        CHECK(x.id == 7);
        CHECK(x.c == color::green);
        const auto y = d.root().get<derived_with_defaults>();
        CHECK(y.id == 7);
        CHECK(y.label == "none");
        const auto z = d.root().get<derived_from_legacy>();
        CHECK(z.id == 7);
        CHECK(z.extra == 3);
    }

    SECTION("other from_json() functions get the value of materialize()")
    {
        const json_document d = json_document::parse(R"({"v": 4})");
        CHECK(d.root().get<legacy>().v == 4);
        CHECK(d.root().get<unconstrained>().v == 4);
        CHECK(d.root().get<constrained>().v == 4);
        legacy l;
        d.root().get_to(l);
        CHECK(l.v == 4);
    }

    SECTION("duplicate keys: members are looked up in the view, where the first one wins")
    {
        const json_document d = json_document::parse(R"({"x": 1, "y": 2, "x": 3})");
        CHECK(d.root().get<point>().x == 1);
        // materialize() keeps the last value, like parse()
        CHECK(d.root().materialize().get<point>().x == 3);
    }

    SECTION("editable documents and ordered_json")
    {
        json_editable_document e = json_editable_document::parse(R"({"x": 1, "y": 2})");
        e.set(e.root(), "x", 10);
        CHECK(e.root().get<point>().x == 10);
        const ordered_json_document o = ordered_json_document::parse(R"({"name": "o", "points": [], "center": {"x": 1, "y": 2}, "named": {}})");
        CHECK(o.root().get<shape>().center.y == 2);
    }

#if !defined(JSON_NOEXCEPTION)
    SECTION("errors are those of the same conversion of a json value")
    {
        const json_document d = json_document::parse(R"([{"x": 1}, {"x": "1", "y": 2}, [1, 2], {"id": "7", "c": "red"}])");
        const json j = d.root().materialize();
        for (std::size_t i = 0; i < 3; ++i)
        {
            CAPTURE(i)
            CHECK(exception_of_call([&] { static_cast<void>(d.root()[i].get<point>()); }) == exception_of_call([&] { static_cast<void>(j[i].get<point>()); }));
        }
        CHECK(exception_of_call([&] { static_cast<void>(d.root()[3].get<derived>()); }) == exception_of_call([&] { static_cast<void>(j[3].get<derived>()); }));
    }
#endif
}

DOCTEST_CLANG_SUPPRESS_WARNING_POP
DOCTEST_GCC_SUPPRESS_WARNING_POP
