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
};

struct shape
{
    std::string name;
    std::vector<point> points;
    point center;
    std::map<std::string, point> named;
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(shape, name, points, center, named)
};

struct with_defaults
{
    int a = 1;
    std::string b = "default";
    std::vector<int> c = {1, 2};
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(with_defaults, a, b, c)

struct with_names
{
    int value = 0;
    std::string text;
};
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

    SECTION("the library's own conversions are not called with a view (and the probe compiles for them)")
    {
        // these go through materialize() (vectors, maps with string keys,
        // strings, and numbers are converted by the view itself)
        static_assert(!reads_view<std::list<int>>::value, "std types");
        static_assert(!reads_view<std::deque<point>>::value, "std types");
        static_assert(!reads_view<std::set<std::string>>::value, "std types");
        static_assert(!reads_view<std::unordered_set<int>>::value, "std types");
        static_assert(!reads_view<std::forward_list<int>>::value, "std types");
        static_assert(!reads_view<std::valarray<double>>::value, "std types");
        static_assert(!reads_view<std::array<int, 3>>::value, "std types");
        static_assert(!reads_view<std::pair<int, std::string>>::value, "std types");
        static_assert(!reads_view<std::tuple<int, bool, point>>::value, "std types");
        static_assert(!reads_view<std::map<int, int>>::value, "std types");
        static_assert(!reads_view<std::unordered_map<int, point>>::value, "std types");
        static_assert(!reads_view<std::map<color, int>>::value, "std types");
        static_assert(!reads_view<std::map<std::string, int>>::value, "std types");
        static_assert(!reads_view<std::vector<point>>::value, "std types");
        static_assert(!reads_view<std::vector<bool>>::value, "std types");
        static_assert(!reads_view<std::vector<std::uint8_t>>::value, "std types");
        static_assert(!reads_view<std::string>::value, "std types");
        static_assert(!reads_view<int>::value, "std types");
        static_assert(!reads_view<bool>::value, "std types");
        static_assert(!reads_view<double>::value, "std types");
        static_assert(!reads_view<std::nullptr_t>::value, "std types");
        static_assert(!reads_view<json>::value, "std types");
        static_assert(!reads_view<json::binary_t>::value, "std types");
#ifdef JSON_HAS_CPP_17
        static_assert(!reads_view<std::optional<point>>::value, "std types");
#endif
        CHECK(true);
    }

    SECTION("macro types")
    {
        const json_document d = json_document::parse(R"({"name": "s", "points": [{"x": 1, "y": 2}, {"x": 3, "y": 4}],
            "center": {"x": 5, "y": 6}, "named": {"a": {"x": 7, "y": 8}}})");
        const shape s = d.root().get<shape>();
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
        const with_defaults w = d.root().get<with_defaults>();
        CHECK(w.a == 5);
        CHECK(w.b == "default");
        CHECK(w.c == std::vector<int> {1, 2});
        const json_document null_document = json_document::parse("null");
        CHECK(null_document.root().get<with_defaults>().a == 1);
        const with_names n = d.root().get<with_names>();
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
        CHECK(exception_of_call([&] { static_cast<void>(d.root()[2].get<strict_color>()); }) == "[json.exception.out_of_range.410] enum value out of range for strict_color: \"purple\"");
#if !JSON_DIAGNOSTICS
        CHECK(exception_of_call([&] { static_cast<void>(d.root()[2].get<strict_color>()); }) == exception_of_call([&] { static_cast<void>(j[2].get<strict_color>()); }));
#endif
#endif
    }

    SECTION("derived types")
    {
        const json_document d = json_document::parse(R"({"id": 7, "c": "green", "extra": 3})");
        const derived x = d.root().get<derived>();
        CHECK(x.id == 7);
        CHECK(x.c == color::green);
        const derived_with_defaults y = d.root().get<derived_with_defaults>();
        CHECK(y.id == 7);
        CHECK(y.label == "none");
        const derived_from_legacy z = d.root().get<derived_from_legacy>();
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

#if !defined(JSON_NOEXCEPTION) && !JSON_DIAGNOSTICS
    SECTION("errors are those of the same conversion of a json value")
    {
        // (with JSON_DIAGNOSTICS, those of json name the path of the value)
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
