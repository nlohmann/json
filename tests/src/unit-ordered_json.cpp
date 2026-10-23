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
using nlohmann::ordered_json;

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

TEST_CASE("ordered_json")
{
    json j;
    ordered_json oj;

    j["element3"] = 3;
    j["element1"] = 1;
    j["element2"] = 2;

    oj["element3"] = 3;
    oj["element1"] = 1;
    oj["element2"] = 2;

    CHECK(j.dump() == "{\"element1\":1,\"element2\":2,\"element3\":3}");
    CHECK(oj.dump() == "{\"element3\":3,\"element1\":1,\"element2\":2}");

    CHECK(j == json(oj));
    CHECK(ordered_json(json(oj)) == ordered_json(j));

    j.erase("element1");
    oj.erase("element1");

    CHECK(j.dump() == "{\"element2\":2,\"element3\":3}");
    CHECK(oj.dump() == "{\"element3\":3,\"element2\":2}");

    // remove again and nothing changes
    j.erase("element1");
    oj.erase("element1");

    CHECK(j.dump() == "{\"element2\":2,\"element3\":3}");
    CHECK(oj.dump() == "{\"element3\":3,\"element2\":2}");

    // There are no dup keys cause constructor calls emplace...
    json const multi {{"z", 1}, {"m", 2}, {"m", 3}, {"y", 4}, {"m", 5}};
    CHECK(multi.size() == 3);
    CHECK(multi.dump() == "{\"m\":2,\"y\":4,\"z\":1}");

    ordered_json multi_ordered {{"z", 1}, {"m", 2}, {"m", 3}, {"y", 4}, {"m", 5}};
    CHECK(multi_ordered.size() == 3);
    CHECK(multi_ordered.dump() == "{\"z\":1,\"m\":2,\"y\":4}");
    CHECK(multi_ordered.erase("m") == 1);
    CHECK(multi_ordered.dump() == "{\"z\":1,\"y\":4}");

    // Ranged insert test.
    // It seems that values shouldn't be overwritten. Only new values are added
    json j1 {{"c", 1}, {"b", 2}, {"a", 3}};
    const json j2 {{"c", 77}, {"d", 42}, {"a", 4}};
    j1.insert( j2.cbegin(), j2.cend() );
    CHECK(j1.size() == 4);
    CHECK(j1.dump() == "{\"a\":3,\"b\":2,\"c\":1,\"d\":42}");

    ordered_json oj1 {{"c", 1}, {"b", 2}, {"a", 3}};
    const ordered_json oj2 {{"c", 77}, {"d", 42}, {"a", 4}};
    oj1.insert( oj2.cbegin(), oj2.cend() );
    CHECK(oj1.size() == 4);
    CHECK(oj1.dump() == "{\"c\":1,\"b\":2,\"a\":3,\"d\":42}");
}

TEST_CASE("regression test for issue #3732 - iteration_proxy_value<iter_impl<ordered_json>>")
{
    // Naming the proxy type in a function-parameter position forces eager
    // instantiation of basic_json<ordered_map>; previously this hit an
    // incomplete-type error in set_parents().
    auto fn = [](nlohmann::detail::iteration_proxy_value<nlohmann::detail::iter_impl<nlohmann::ordered_json>> const & val)
    {
        return val.value();
    };
    static_cast<void>(fn);
}

TEST_CASE("copying an ordered_json with nested values")
{
    // ordered_map is backed by a vector, so copying an object that has
    // structured values takes a different route than copying a std::map-backed
    // one; see https://github.com/nlohmann/json/issues/5387
    ordered_json oj;
    oj["z"] = 1;
    oj["a"]["y"] = 2;
    oj["a"]["b"]["x"] = 3;
    oj["m"] = {1, 2, {{"w", 4}}};

    const ordered_json copy(oj);

    SECTION("the copy is equal to the original")
    {
        CHECK(copy == oj);
        CHECK(copy.dump() == oj.dump());
    }

    SECTION("the key order is preserved at every level")
    {
        CHECK(copy.dump() == R"({"z":1,"a":{"y":2,"b":{"x":3}},"m":[1,2,{"w":4}]})");
    }

    SECTION("the copy is independent of the original")
    {
        ordered_json mutated(oj);
        mutated["a"]["b"]["x"] = 99;

        CHECK(oj["a"]["b"]["x"] == 3);
        CHECK(mutated["a"]["b"]["x"] == 99);
    }
}

TEST_CASE("regression test - diff() must account for ordered_json member order")
{
    SECTION("pure reorder, no value changes")
    {
        ordered_json a = {{"a", 1}, {"b", 2}};
        ordered_json b = {{"b", 2}, {"a", 1}};
        CHECK(a != b); // order-sensitive equality
        CHECK(a.patch(ordered_json::diff(a, b)) == b);
    }

    SECTION("new key must land at the front")
    {
        ordered_json c = {{"b", 2}};
        ordered_json e = {{"a", 1}, {"b", 2}};
        CHECK(c.patch(ordered_json::diff(c, e)) == e);
    }

    SECTION("reorder plus a value change on one of the reordered keys")
    {
        ordered_json a = {{"a", 1}, {"b", 2}};
        ordered_json b = {{"b", 20}, {"a", 1}};
        CHECK(a != b);
        CHECK(a.patch(ordered_json::diff(a, b)) == b);
    }

    SECTION("reorder plus a deleted key")
    {
        ordered_json a = {{"a", 1}, {"b", 2}, {"c", 3}};
        ordered_json b = {{"b", 2}, {"a", 1}};
        CHECK(a != b);
        CHECK(a.patch(ordered_json::diff(a, b)) == b);
    }

    SECTION("reorder plus a nested value that itself needs a recursive diff")
    {
        ordered_json a = {{"a", {{"x", 1}, {"y", 2}}}, {"b", 2}};
        ordered_json b = {{"b", 2}, {"a", {{"x", 1}, {"y", 99}}}};
        CHECK(a != b);
        CHECK(a.patch(ordered_json::diff(a, b)) == b);
    }

    SECTION("three or more keys shuffled into a different order")
    {
        ordered_json a = {{"a", 1}, {"b", 2}, {"c", 3}, {"d", 4}};
        ordered_json b = {{"d", 4}, {"b", 2}, {"a", 1}, {"c", 3}};
        CHECK(a != b);
        CHECK(a.patch(ordered_json::diff(a, b)) == b);
    }

    SECTION("matching order still produces a minimal patch (fast path unaffected)")
    {
        ordered_json a = {{"a", 1}, {"b", 2}, {"c", 3}};
        ordered_json b = {{"a", 1}, {"b", 20}, {"c", 3}};
        auto p = ordered_json::diff(a, b);
        // only the changed value should be touched, not a wholesale remove+add
        CHECK(p.size() == 1);
        CHECK(p[0]["op"] == "replace");
        CHECK(p[0]["path"] == "/b");
        CHECK(a.patch(p) == b);
    }

    SECTION("plain json (std::map-backed) is unaffected by same-key-different-insertion-order")
    {
        json a;
        a["b"] = 2;
        a["a"] = 1;

        json b;
        b["a"] = 1;
        b["b"] = 2;

        // std::map iteration is always sorted by key, so a == b regardless of
        // insertion order, and diff() must still produce the same minimal
        // (empty) result as before this fix
        CHECK(a == b);
        auto p = json::diff(a, b);
        CHECK(p.empty());
        CHECK(a.patch(p) == b);
    }
}

TEST_CASE("regression test for issue #5673 - ordered_json::emplace with a non-rvalue value")
{
    SECTION("lvalue value")
    {
        ordered_json oj = ordered_json::object();
        ordered_json value = 1;
        auto res = oj.emplace("a", value);
        CHECK(res.second == true);
        CHECK(oj.dump() == "{\"a\":1}");
    }

    SECTION("const lvalue value")
    {
        ordered_json oj = ordered_json::object();
        const ordered_json value = 1;
        auto res = oj.emplace("a", value);
        CHECK(res.second == true);
        CHECK(oj.dump() == "{\"a\":1}");
    }

    SECTION("rvalue value")
    {
        ordered_json oj = ordered_json::object();
        auto res = oj.emplace("a", ordered_json(1));
        CHECK(res.second == true);
        CHECK(oj.dump() == "{\"a\":1}");
    }

    SECTION("existing key is not overwritten (std::map-compatible semantics)")
    {
        ordered_json oj = ordered_json::object();
        ordered_json value = 1;
        oj.emplace("a", value);

        ordered_json other_value = 2;
        auto res = oj.emplace("a", other_value);
        CHECK(res.second == false);
        CHECK(oj.dump() == "{\"a\":1}");
    }
}

namespace
{
// the sizes around which the DOM parser changes how it stores the elements of
// an array (16) and the members of an object in a vector (32, and 64 for the
// key index)
const std::array<std::size_t, 17> container_sizes = {{0, 1, 2, 3, 15, 16, 17, 18, 31, 32, 33, 34, 63, 64, 65, 66, 200}};

template<typename Json>
std::string array_text(const std::size_t n, const std::size_t depth)
{
    std::string text = "[";
    for (std::size_t i = 0; i < n; ++i)
    {
        text += (i == 0 ? "" : ",");
        // alternate scalars, empty containers and nested containers
        switch (i % 4)
        {
            case 0:
                text += std::to_string(i);
                break;
            case 1:
                text += "\"s" + std::to_string(i) + "\"";
                break;
            case 2:
                text += depth == 0 ? "[]" : array_text<Json>(n / 2, depth - 1);
                break;
            default:
                text += depth == 0 ? "{}" : "{\"a\":" + array_text<Json>(n / 3, depth - 1) + ",\"b\":null}";
                break;
        }
    }
    return text + "]";
}

template<typename Json>
std::string object_text(const std::size_t n, const std::size_t depth, const bool duplicates)
{
    std::string text = "{";
    for (std::size_t i = 0; i < n; ++i)
    {
        text += (i == 0 ? "" : ",");
        text += "\"key" + std::to_string(i) + "\":";
        switch (i % 4)
        {
            case 0:
                text += std::to_string(i);
                break;
            case 1:
                text += depth == 0 ? "[]" : array_text<Json>(n / 2, depth - 1);
                break;
            case 2:
                text += depth == 0 ? "{}" : object_text<Json>(n / 2, depth - 1, duplicates);
                break;
            default:
                text += "\"value\"";
                break;
        }
    }
    if (duplicates)
    {
        // keys that are there already, the first and the last one, with other values
        text += n == 0 ? "" : ",";
        text += R"("key0":[1,2],"key)";
        text += std::to_string(n - 1);
        text += R"(":{"again":true})";
    }
    return text + "}";
}

template<typename Json>
void check_same_dump(const std::string& text)
{
    // the text is what dump() writes for the parsed value, and the value
    // survives a second round trip: arrays keep their elements in order, an
    // ordered_json keeps its members in order of appearance
    const Json parsed = Json::parse(text);
    const Json again = Json::parse(parsed.dump());
    CHECK(parsed == again);
    CHECK(parsed.dump() == again.dump());
    CHECK(Json::accept(text));
}
} // namespace

TEST_CASE("parsing containers of sizes around the limits of the DOM parser")
{
    SECTION("arrays")
    {
        for (const std::size_t n : container_sizes)
        {
            const std::string text = array_text<json>(n, 2);
            INFO("size ", n);

            const json parsed = json::parse(text);
            CHECK(parsed.is_array());
            CHECK(parsed.size() == n);
            for (std::size_t i = 0; i < n; i += 4)
            {
                CHECK(parsed[i] == i);
            }
            check_same_dump<json>(text);
            check_same_dump<ordered_json>(text);
            CHECK(ordered_json::parse(text).dump() == parsed.dump());
        }
    }

    SECTION("objects")
    {
        for (const bool duplicates :
                {
                    false, true
                })
        {
            for (const std::size_t n : container_sizes)
            {
                const std::string text = object_text<json>(n, 2, duplicates);
                INFO("size ", n, " duplicates ", duplicates);

                const json parsed = json::parse(text);
                const ordered_json ordered = ordered_json::parse(text);
                CHECK(parsed.is_object());
                CHECK(ordered.is_object());
                CHECK(parsed.size() == ordered.size());
                // the same members, in the order of their first appearance
                std::size_t i = 0;
                for (auto it = ordered.begin(); it != ordered.end(); ++it, ++i)
                {
                    if (i < n)
                    {
                        CHECK(it.key() == "key" + std::to_string(i));
                    }
                    CHECK(parsed.at(it.key()) == json(it.value()));
                }
                if (duplicates && n > 1)
                {
                    // the later value replaced the earlier one in its place
                    CHECK(ordered.at("key0") == ordered_json::parse("[1,2]"));
                    CHECK(ordered.at("key" + std::to_string(n - 1)) == ordered_json::parse("{\"again\":true}"));
                    CHECK(ordered.begin().key() == "key0");
                    CHECK(ordered.size() == n);
                }
                check_same_dump<json>(text);
                check_same_dump<ordered_json>(text);
            }
        }
    }

    SECTION("objects with many different and repeated keys")
    {
        // 300 members of which a third repeat an earlier key
        std::string text = "{";
        for (std::size_t i = 0; i < 300; ++i)
        {
            text += (i == 0 ? "" : ",");
            text += "\"k" + std::to_string(i % 200) + "\":" + std::to_string(i);
        }
        text += '}';

        const ordered_json ordered = ordered_json::parse(text);
        const json parsed = json::parse(text);
        CHECK(ordered.size() == 200);
        CHECK(parsed.size() == 200);
        std::size_t i = 0;
        for (auto it = ordered.begin(); it != ordered.end(); ++it, ++i)
        {
            CHECK(it.key() == "k" + std::to_string(i));
            // the last value written
            CHECK(it.value() == (i < 100 ? i + 200 : i));
            CHECK(parsed.at(it.key()) == json(it.value()));
        }
    }
}

namespace
{
// a deterministic source of structure for parsing tests: builds a JSON text
// and, at the same time, the value it has to parse to
class tree_generator
{
  public:
    explicit tree_generator(std::uint32_t seed) : state(seed) {}

    template<typename Json>
    Json make(std::string& text, const std::size_t depth)
    {
        switch (next(depth == 0 ? 5 : 9))
        {
            case 0:
                text += "null";
                return Json(nullptr);
            case 1:
                text += "true";
                return Json(true);
            case 2:
            {
                const int n = static_cast<int>(next(2000)) - 1000;
                text += std::to_string(n);
                return Json(n);
            }
            case 3:
                text += "\"text\"";
                return Json("text");
            case 4:
                text += "2.5";
                return Json(2.5);
            case 5:
            case 6:
            case 7:
            {
                Json array = Json::array();
                text += '[';
                const std::size_t n = size();
                for (std::size_t i = 0; i < n; ++i)
                {
                    text += (i == 0 ? "" : ",");
                    array.push_back(make<Json>(text, depth - 1));
                }
                text += ']';
                return array;
            }
            default:
            {
                Json object = Json::object();
                text += '{';
                const std::size_t n = size();
                for (std::size_t i = 0; i < n; ++i)
                {
                    const std::string key = "k" + std::to_string(i);
                    text += (i == 0 ? "\"" : ",\"") + key + "\":";
                    object[key] = make<Json>(text, depth - 1);
                }
                text += '}';
                return object;
            }
        }
    }

  private:
    std::uint32_t next(const std::uint32_t bound)
    {
        state = (state * 1664525U) + 1013904223U;
        return (state >> 8) % bound;
    }

    std::size_t size()
    {
        return container_sizes[next(static_cast<std::uint32_t>(container_sizes.size()))];
    }

    std::uint32_t state;
};
} // namespace

TEST_CASE("parsing random trees of arrays and objects")
{
    for (std::uint32_t seed = 1; seed <= 150; ++seed)
    {
        INFO("seed ", seed);

        std::string text;
        std::string ordered_text;
        const json expected = tree_generator(seed).make<json>(text, 3);
        const auto ordered_expected = tree_generator(seed).make<ordered_json>(ordered_text, 3);
        CHECK(text == ordered_text);

        CHECK(json::parse(text) == expected);
        CHECK(json::accept(text));
        const ordered_json ordered = ordered_json::parse(text);
        CHECK(ordered == ordered_expected);
        CHECK(ordered.dump() == ordered_expected.dump());
        CHECK(json::parse(text).dump() == expected.dump());
    }
}
