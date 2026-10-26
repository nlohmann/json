//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <array>
#include <deque>
#include <forward_list>
#include <list>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <valarray>
#include <vector>

#if (defined(__cplusplus) && __cplusplus >= 201703L) || (defined(_HAS_CXX17) && _HAS_CXX17 == 1)
    #if __has_include(<filesystem>)
        #include <filesystem>
        #define TO_JSON_RVALUE_HAS_FS 1
    #endif
#endif

namespace
{
// element type that counts how it is converted to JSON: a conversion from an
// lvalue copies, a conversion from an rvalue moves
struct tracked
{
    std::string payload;
    bool moved_from = false;

    explicit tracked(std::string p) noexcept : payload(std::move(p)) {}
    tracked(const tracked&) = default;
    tracked& operator=(const tracked&) = default;
    tracked(tracked&& other) noexcept : payload(std::move(other.payload)), moved_from(other.moved_from)
    {
        other.moved_from = true;
    }
    // not needed by the tests (and an unused definition fails -Wunneeded-member-function)
    tracked& operator=(tracked&&) = delete;
    ~tracked() = default;
};

int tracked_copies = 0; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables,misc-use-internal-linkage)
int tracked_moves = 0;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables,misc-use-internal-linkage)

void to_json(json& j, const tracked& t)
{
    ++tracked_copies;
    j = t.payload;
}

void to_json(json& j, tracked&& t)
{
    ++tracked_moves;
    j = std::move(t.payload);
    t.moved_from = true;
}

// user type with its own rvalue-aware serializer
struct udt_container
{
    std::vector<int> values;
};
} // namespace

namespace nlohmann
{
template<>
struct adl_serializer<udt_container>
{
    static void to_json(json& j, const udt_container& c)
    {
        j = c.values;
        j.push_back("copied");
    }
    static void to_json(json& j, udt_container&& c)
    {
        j = std::move(c.values);
        j.push_back("moved");
    }
};
} // namespace nlohmann

TEST_CASE("to_json from rvalue containers")
{
    const std::string long_a(64, 'a');
    const std::string long_b(64, 'b');

    SECTION("vector<std::string>: elements are moved")
    {
        std::vector<std::string> v{long_a, long_b};
        const json j = std::move(v);
        CHECK(j == json::array({long_a, long_b}));
        for (const auto& s : v) // NOLINT(bugprone-use-after-move,hicpp-invalid-access-moved)
        {
            CHECK(s.empty()); // long strings leave the source element empty when moved
        }
    }

    SECTION("vector<std::string>: lvalues are copied and left untouched")
    {
        const std::vector<std::string> v{long_a, long_b};
        const json j = v;
        CHECK(j == json::array({long_a, long_b}));
        CHECK(v[0] == long_a);
        CHECK(v[1] == long_b);

        std::vector<std::string> v2{long_a, long_b};
        const json j2 = v2;
        CHECK(j2 == j);
        CHECK(v2[0] == long_a);
        CHECK(v2[1] == long_b);
    }

    SECTION("tracked elements: rvalue moves, lvalue copies")
    {
        tracked_copies = 0;
        tracked_moves = 0;

        std::vector<tracked> v;
        v.emplace_back("x");
        v.emplace_back("y");

        const json copy = v;
        CHECK(copy == json::array({"x", "y"}));
        CHECK(tracked_copies == 2);
        CHECK(tracked_moves == 0);
        CHECK_FALSE(v[0].moved_from);

        const json moved = std::move(v);
        CHECK(moved == copy);
        CHECK(tracked_copies == 2);
        CHECK(tracked_moves == 2);
    }

    SECTION("const rvalue is copied")
    {
        tracked_copies = 0;
        tracked_moves = 0;
        const std::vector<tracked> v(2, tracked("z"));
        const json j = std::move(v); // NOLINT(performance-move-const-arg,hicpp-move-const-arg)
        CHECK(j == json::array({"z", "z"}));
        CHECK(tracked_copies == 2);
        CHECK(tracked_moves == 0);
    }

    SECTION("other sequence containers")
    {
        CHECK(json(std::deque<std::string> {long_a, long_b}) == json::array({long_a, long_b}));
        CHECK(json(std::list<std::string> {long_a, long_b}) == json::array({long_a, long_b}));
        CHECK(json(std::forward_list<std::string> {long_a, long_b}) == json::array({long_a, long_b}));
        CHECK(json(std::array<std::string, 2> {{long_a, long_b}}) == json::array({long_a, long_b}));
        CHECK(json(std::set<std::string> {long_a, long_b}) == json::array({long_a, long_b}));
        CHECK(json(std::vector<bool> {true, false}) == json::array({true, false}));
        CHECK(json(std::vector<int> {1, 2, 3}) == json::array({1, 2, 3}));
        CHECK(json(std::vector<std::vector<std::string>> {{long_a}, {long_b}}) == json::array({json::array({long_a}), json::array({long_b})}));
        CHECK(json(std::vector<json> {1, "a"}) == json::array({1, "a"}));
    }

    SECTION("valarray")
    {
        std::valarray<int> va(3);
        va[0] = 1;
        va[1] = 2;
        va[2] = 3;
        CHECK(json(std::move(va)) == json::array({1, 2, 3})); // NOLINT(performance-move-const-arg,hicpp-move-const-arg)
        CHECK(json(std::valarray<int>(2)) == json::array({0, 0}));
    }

    SECTION("array_t and json arrays")
    {
        json::array_t arr{1, 2};
        CHECK(json(std::move(arr)) == json::array({1, 2}));
        json a = json::array({1, 2});
        const json b = std::move(a);
        CHECK(b == json::array({1, 2}));
    }

    SECTION("object-like containers")
    {
        std::map<std::string, std::string> m{{"a", long_a}, {"b", long_b}};
        const json j = std::move(m);
        CHECK(j == json({{"a", long_a}, {"b", long_b}}));
        for (const auto& kv : m) // NOLINT(bugprone-use-after-move,hicpp-invalid-access-moved)
        {
            CHECK(kv.second.empty()); // values moved, keys (const) copied
        }

        const std::map<std::string, std::string> cm{{"a", long_a}};
        const json jc = cm;
        CHECK(jc["a"] == long_a);
        CHECK(cm.at("a") == long_a);

        std::unordered_map<std::string, std::string> um{{"a", long_a}};
        CHECK(json(std::move(um)) == json({{"a", long_a}}));

        std::multimap<std::string, int> mm{{"a", 1}};
        CHECK(json(std::move(mm)) == json({{"a", 1}}));

        tracked_copies = 0;
        tracked_moves = 0;
        std::map<std::string, tracked> mt;
        mt.emplace("k", tracked("v"));
        const json jt = std::move(mt);
        CHECK(jt == json({{"k", "v"}}));
        CHECK(tracked_moves == 1);
        CHECK(tracked_copies == 0);

        json::object_t obj{{"a", 1}};
        CHECK(json(std::move(obj)) == json({{"a", 1}}));
    }

    SECTION("user type with its own to_json overloads")
    {
        udt_container c{{1, 2}};
        const json lv = c;
        CHECK(lv == json::array({1, 2, "copied"}));
        const json rv = std::move(c);
        CHECK(rv == json::array({1, 2, "moved"}));
    }

    SECTION("assignment and implicit conversion")
    {
        std::vector<std::string> v{long_a};
        json j;
        j = std::move(v);
        CHECK(j == json::array({long_a}));
        json k = {std::vector<std::string>{long_b}};
        CHECK(k.size() == 1);
    }

#ifdef TO_JSON_RVALUE_HAS_FS
    SECTION("std::filesystem::path rvalue is still a string")
    {
        CHECK(json(std::filesystem::path("a/b")) == json("a/b"));
#ifdef __cpp_lib_char8_t
        CHECK(json(std::u8string(u8"a/b")) == json("a/b"));
#endif
    }
#endif
}
