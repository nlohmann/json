//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#ifdef JSON_DIAGNOSTICS
    #undef JSON_DIAGNOSTICS
#endif

#define JSON_DIAGNOSTICS 1

#include <nlohmann/json.hpp>
using nlohmann::json;

TEST_CASE("Better diagnostics")
{
    SECTION("empty JSON Pointer")
    {
        json const j = 1;
        std::string s;
        CHECK_THROWS_WITH_AS(s = j.get<std::string>(), "[json.exception.type_error.302] type must be string, but is number", json::type_error);
    }

    SECTION("invalid type")
    {
        json j;
        j["a"]["b"]["c"] = 1;
        std::string s;
        CHECK_THROWS_WITH_AS(s = j["a"]["b"]["c"].get<std::string>(), "[json.exception.type_error.302] (/a/b/c) type must be string, but is number", json::type_error);
    }

    SECTION("missing key")
    {
        json j;
        j["object"]["object"] = true;
        CHECK_THROWS_WITH_AS(j["object"].at("not_found"), "[json.exception.out_of_range.403] (/object) key 'not_found' not found", json::out_of_range);
    }

    SECTION("array index out of range")
    {
        json j;
        j["array"][4] = true;
        CHECK_THROWS_WITH_AS(j["array"].at(5), "[json.exception.out_of_range.401] (/array) array index 5 is out of range", json::out_of_range);
    }

    SECTION("array index at wrong type")
    {
        json j;
        j["array"][4] = true;
        CHECK_THROWS_WITH_AS(j["array"][4][5], "[json.exception.type_error.305] (/array/4) cannot use operator[] with a numeric argument with boolean", json::type_error);
    }

    SECTION("wrong iterator")
    {
        json j;
        j["array"] = json::array();
        CHECK_THROWS_WITH_AS(j["array"].erase(j.begin()), "[json.exception.invalid_iterator.202] (/array) iterator does not fit current value", json::invalid_iterator);
    }

    SECTION("JSON Pointer escaping")
    {
        json j;
        j["a/b"]["m~n"] = 1;
        std::string s;
        CHECK_THROWS_WITH_AS(s = j["a/b"]["m~n"].get<std::string>(), "[json.exception.type_error.302] (/a~1b/m~0n) type must be string, but is number", json::type_error);
    }

    SECTION("Parse error")
    {
        json _;
        CHECK_THROWS_WITH_AS(_ = json::parse(""), "[json.exception.parse_error.101] parse error at line 1, column 1: attempting to parse an empty input; check that your input string or stream contains the expected JSON", json::parse_error);
    }

    SECTION("Wrong type in update()")
    {
        json j = {{"foo", "bar"}};
        json k = {{"bla", 1}};

        CHECK_THROWS_WITH_AS(j.update(k["bla"].begin(), k["bla"].end()), "[json.exception.type_error.312] (/bla) cannot use update() with number", json::type_error);
        CHECK_THROWS_WITH_AS(j.update(k["bla"]), "[json.exception.type_error.312] (/bla) cannot use update() with number", json::type_error);
    }
}

TEST_CASE("Regression tests for extended diagnostics")
{
    SECTION("Regression test for https://github.com/nlohmann/json/pull/2562#pullrequestreview-574858448")
    {
        CHECK_THROWS_WITH_AS(json({"0", "0"})[1].get<int>(), "[json.exception.type_error.302] (/1) type must be number, but is string", json::type_error);
        CHECK_THROWS_WITH_AS(json({"0", "1"})[1].get<int>(), "[json.exception.type_error.302] (/1) type must be number, but is string", json::type_error);
    }

    SECTION("Regression test for https://github.com/nlohmann/json/pull/2562/files/380a613f2b5d32425021129cd1f371ddcfd54ddf#r563259793")
    {
        json j;
        j["/foo"] = {1, 2, 3};
        CHECK_THROWS_WITH_AS(j.unflatten(), "[json.exception.type_error.315] (/~1foo) values in object must be primitive", json::type_error);
    }

    SECTION("Regression test for issue #2838 - Assertion failure when inserting into arrays with JSON_DIAGNOSTICS set")
    {
        // void push_back(basic_json&& val)
        {
            json j_arr = json::array();
            j_arr.push_back(json::object());
            j_arr.push_back(json::object());
            j_arr.push_back(json::object());
            j_arr.push_back(json::object());
            json j_obj = json::object();
            j_obj["key"] = j_arr;
        }

        // void push_back(const basic_json& val)
        {
            json j_arr = json::array();
            auto object = json::object();
            j_arr.push_back(object);
            j_arr.push_back(object);
            j_arr.push_back(object);
            j_arr.push_back(object);
            json j_obj = json::object();
            j_obj["key"] = j_arr;
        }

        // reference emplace_back(Args&& ... args)
        {
            json j_arr = json::array();
            j_arr.emplace_back(json::object());
            j_arr.emplace_back(json::object());
            j_arr.emplace_back(json::object());
            j_arr.emplace_back(json::object());
            json j_obj = json::object();
            j_obj["key"] = j_arr;
        }

        // iterator insert(const_iterator pos, const basic_json& val)
        {
            json j_arr = json::array();
            j_arr.insert(j_arr.begin(), json::object());
            j_arr.insert(j_arr.begin(), json::object());
            j_arr.insert(j_arr.begin(), json::object());
            j_arr.insert(j_arr.begin(), json::object());
            json j_obj = json::object();
            j_obj["key"] = j_arr;
        }

        // iterator insert(const_iterator pos, size_type cnt, const basic_json& val)
        {
            json j_arr = json::array();
            j_arr.insert(j_arr.begin(), 2, json::object());
            json j_obj = json::object();
            j_obj["key"] = j_arr;
        }

        // iterator insert(const_iterator pos, const_iterator first, const_iterator last)
        {
            json j_arr = json::array();
            json j_objects = {json::object(), json::object()};
            j_arr.insert(j_arr.begin(), j_objects.begin(), j_objects.end());
            json j_obj = json::object();
            j_obj["key"] = j_arr;
        }
    }

    SECTION("Regression test for issue #2962 - JSON_DIAGNOSTICS assertion for ordered_json")
    {
        nlohmann::ordered_json j;
        nlohmann::ordered_json j2;
        const std::string value;
        j["first"] = value;
        j["second"] = value;
        j2["something"] = j;
    }

    SECTION("Regression test for issue #3007 - Parent pointers properly set when using update()")
    {
        // void update(const_reference j)
        {
            json j = json::object();

            {
                json j2 = json::object();
                j2["one"] = 1;

                j.update(j2);
            }

            // Must call operator[] on const element, otherwise m_parent gets updated.
            auto const& constJ = j;
            CHECK_THROWS_WITH_AS(constJ["one"].at(0), "[json.exception.type_error.304] (/one) cannot use at() with number", json::type_error);
        }

        // void update(const_iterator first, const_iterator last)
        {
            json j = json::object();

            {
                json j2 = json::object();
                j2["one"] = 1;

                j.update(j2.begin(), j2.end());
            }

            // Must call operator[] on const element, otherwise m_parent gets updated.
            auto const& constJ = j;
            CHECK_THROWS_WITH_AS(constJ["one"].at(0), "[json.exception.type_error.304] (/one) cannot use at() with number", json::type_error);
        }

        // Code from #3007 triggering unwanted assertion without fix to update().
        {
            json root = json::array();
            json lower = json::object();

            {
                json lowest = json::object();
                lowest["one"] = 1;

                lower.update(lowest);
            }

            root.push_back(lower);
        }
    }

    SECTION("Regression test for issue #3032 - Yet another assertion failure when inserting into arrays with JSON_DIAGNOSTICS set")
    {
        // reference operator[](size_type idx)
        {
            json j_arr = json::array();
            j_arr[0] = 0;
            j_arr[1] = 1;
            j_arr[2] = 2;
            j_arr[3] = 3;
            j_arr[4] = 4;
            j_arr[5] = 5;
            j_arr[6] = 6;
            j_arr[7] = 7;
            json const j_arr_copy = j_arr;
        }
    }

    SECTION("Regression test for issue #3915 - JSON_DIAGNOSTICS trigger assertion")
    {
        json j = json::object();
        j["root"] = "root_str";

        json jj = json::object();
        jj["child"] = json::object();

        // If do not push anything in object, then no assert will be produced
        jj["child"]["prop1"] = "prop1_value";

        // Push all properties of child in parent
        j.insert(jj.at("child").begin(), jj.at("child").end());

        // Here assert is generated when construct new json
        const json k(j);

        CHECK(k.dump() == "{\"prop1\":\"prop1_value\",\"root\":\"root_str\"}");
    }

    SECTION("Regression test for issue #4813 - update() with merge_objects=true triggers JSON_ASSERT with JSON_DIAGNOSTICS")
    {
        // https://github.com/nlohmann/json/issues/4813
        nlohmann::ordered_json j1 = {{"numbers", {{"one", 1}}}};
        nlohmann::ordered_json const j2 = {{"numbers", {{"two", 2}}}, {"string", "t"}};
        CHECK_NOTHROW(j1.update(j2, true));
        CHECK(j1["numbers"]["one"] == 1);
        CHECK(j1["numbers"]["two"] == 2);
        CHECK(j1["string"] == "t");
    }

    SECTION("Regression test for issue #5387 - copying keeps the parents of nested values")
    {
        // A value nested deeper than the copy constructor's descent bound is
        // copied without the call stack. Every container that path creates has
        // to have the parents of its children set, or the JSON Pointer in the
        // diagnostic is cut short.
        const std::size_t depth = 300;

        SECTION("objects")
        {
            json j = "not a number";
            std::string pointer;
            for (std::size_t i = 0; i < depth; ++i)
            {
                j = json{{"a", j}};
                pointer += "/a";
            }

            json const copy(j); // NOLINT(performance-unnecessary-copy-initialization)

            const json* inner = &copy;
            for (std::size_t i = 0; i < depth; ++i)
            {
                inner = &inner->at("a");
            }

            std::string const expected = "[json.exception.type_error.302] (" + pointer + ") type must be number, but is string";
            int i = 0;
            CHECK_THROWS_WITH_AS(i = inner->get<int>(), expected.c_str(), json::type_error);
            CHECK(i == 0);
        }

        SECTION("arrays")
        {
            json j = "not a number";
            std::string pointer;
            for (std::size_t i = 0; i < depth; ++i)
            {
                j = json::array({j});
                pointer += "/0";
            }

            json const copy(j); // NOLINT(performance-unnecessary-copy-initialization)

            const json* inner = &copy;
            for (std::size_t i = 0; i < depth; ++i)
            {
                inner = &inner->at(0);
            }

            std::string const expected = "[json.exception.type_error.302] (" + pointer + ") type must be number, but is string";
            int i = 0;
            CHECK_THROWS_WITH_AS(i = inner->get<int>(), expected.c_str(), json::type_error);
            CHECK(i == 0);
        }
    }

    SECTION("Regression test - swap(array_t&)/swap(object_t&) must update JSON_DIAGNOSTICS parent pointers")
    {
        // swap(array_t&)
        {
            json j = json::array();
            json::array_t arr = {json::array({1})};
            j.swap(arr);

            // parent pointers of the moved-in elements must point into j, not
            // into the now-defunct free-standing array_t
            CHECK_THROWS_WITH_AS(j[0][0].get<std::string>(), "[json.exception.type_error.302] (/0/0) type must be string, but is number", json::type_error);

            // must not trigger assert_invariant() in a debug/assert-enabled build
            json const k = j;
            CHECK(k == j);
        }

        // swap(object_t&)
        {
            json o = json::object();
            json::object_t obj = {{"a", json::array({1})}};
            o.swap(obj);

            CHECK_THROWS_WITH_AS(o["a"][0].get<std::string>(), "[json.exception.type_error.302] (/a/0) type must be string, but is number", json::type_error);

            // must not trigger assert_invariant() in a debug/assert-enabled build
            json const p = o;
            CHECK(p == o);
        }
    }

    SECTION("Regression test - erase() and update() must keep JSON_DIAGNOSTICS parent pointers of ordered_json members")
    {
        // ordered_json keeps its members in a vector: erasing a member
        // re-constructs all members after it in place, and adding a key may
        // reallocate the vector; both reset the parent pointers of the members
        // that were moved
        using nlohmann::ordered_json;

        const auto check_parents = [](const ordered_json & j)
        {
            // const access, so operator[] cannot repair the parent pointers
            CHECK_THROWS_WITH_AS(j["z"]["x"].at(0), "[json.exception.type_error.304] (/z/x) cannot use at() with number", ordered_json::type_error);

            // must not trigger assert_invariant() in a debug/assert-enabled build
            ordered_json const copy = j; // NOLINT(performance-unnecessary-copy-initialization)
            CHECK(copy == j);
        };

        // erase(key)
        {
            ordered_json j = {{"a", 1}, {"z", {{"x", 1}}}};
            CHECK(j.erase("a") == 1);
            check_parents(j);
        }

        // erase(iterator)
        {
            ordered_json j = {{"a", 1}, {"z", {{"x", 1}}}};
            j.erase(j.begin());
            check_parents(j);
        }

        // erase(iterator, iterator)
        {
            ordered_json j = {{"a", 1}, {"b", 2}, {"z", {{"x", 1}}}};
            j.erase(j.begin(), j.find("z"));
            check_parents(j);
        }

        // patch() removes via erase(iterator)
        {
            ordered_json j = {{"a", 1}, {"z", {{"x", 1}}}};
            j.patch_inplace(ordered_json::parse(R"([{"op": "remove", "path": "/a"}])"));
            check_parents(j);
        }

        // update(j)
        {
            ordered_json j = {{"z", {{"x", 1}}}};
            j.update({{"a", 1}, {"b", 2}});
            check_parents(j);
        }

        // update(j, true), the outer and the nested vector both grow
        {
            ordered_json j = {{"z", {{"x", 1}}}};
            j.update({{"z", {{"y", 2}}}, {"a", 1}}, true);
            check_parents(j);
        }

        // update(j, true) around its descent bound, where the nested vectors
        // grow while the objects are merged without recursing
        for (const std::size_t depth :
                {
                    nlohmann::detail::recursion_depth_limit() - 1, nlohmann::detail::recursion_depth_limit(), nlohmann::detail::recursion_depth_limit() + 2
                })
        {
            ordered_json j = {{"z", {{"x", 1}}}};
            ordered_json patch = {{"a", 1}, {"b", 2}, {"c", {{"d", 3}}}};
            for (std::size_t i = 0; i < depth; ++i)
            {
                j = ordered_json{{"k", 0}, {"n", std::move(j)}};
                patch = ordered_json{{"n", std::move(patch)}, {"l", 1}, {"m", 2}};
            }
            j.update(patch, true);

            // must not trigger assert_invariant() on any level in a
            // debug/assert-enabled build
            ordered_json const copy = j; // NOLINT(performance-unnecessary-copy-initialization)
            CHECK(copy == j);
        }

        // merge_patch() inserts "c" and removes "d" at /a/c, then inserts "e"
        // at /a, which copies /a/c
        {
            auto j = ordered_json::parse(R"({"a": {"c": {"d": {}}}})");
            j.merge_patch(ordered_json::parse(R"({"a": {"c": {"c": "s", "d": null}, "e": "s"}})"));
            CHECK(j.dump() == R"({"a":{"c":{"c":"s"},"e":"s"}})");

            auto const& constJ = j;
#if JSON_DIAGNOSTIC_POSITIONS
            CHECK_THROWS_WITH_AS(constJ["a"]["c"]["c"].at(0), "[json.exception.type_error.304] (/a/c/c) (bytes 18-21) cannot use at() with string", ordered_json::type_error);
#else
            CHECK_THROWS_WITH_AS(constJ["a"]["c"]["c"].at(0), "[json.exception.type_error.304] (/a/c/c) cannot use at() with string", ordered_json::type_error);
#endif
            ordered_json const copy = j;
            CHECK(copy == j);
        }
    }
}

TEST_CASE("Better diagnostics past the descent bound of update() and merge_patch()")
{
    // Both merge objects nested more than detail::recursion_depth_limit()
    // (128) levels deep without recursing; the values they add or replace
    // there must still know their parents.
    // The values are built rather than parsed, so that the expected messages
    // carry no byte positions under JSON_DIAGNOSTIC_POSITIONS.
    const std::size_t depth = 200;
    json target = {{"x", 1}};
    json patch = {{"y", 2}};
    std::string path;
    for (std::size_t i = 0; i < depth; ++i)
    {
        target = json{{"a", std::move(target)}};
        patch = json{{"a", std::move(patch)}};
        path += "/a";
    }
    const std::string expected_x = "[json.exception.type_error.304] (" + path + "/x) cannot use at() with number";
    const std::string expected_y = "[json.exception.type_error.304] (" + path + "/y) cannot use at() with number";

    SECTION("update()")
    {
        json j = target;
        j.update(patch, true);

        // walk down through const references, which leave m_parent alone
        const json* p = &j;
        for (std::size_t i = 0; i < depth; ++i)
        {
            p = &p->at("a");
        }
        CHECK_THROWS_WITH_AS(p->at("x").at(0), expected_x.c_str(), json::type_error);
        CHECK_THROWS_WITH_AS(p->at("y").at(0), expected_y.c_str(), json::type_error);
    }

    SECTION("merge_patch()")
    {
        json j = target;
        j.merge_patch(patch);

        const json* p = &j;
        for (std::size_t i = 0; i < depth; ++i)
        {
            p = &p->at("a");
        }
        CHECK_THROWS_WITH_AS(p->at("x").at(0), expected_x.c_str(), json::type_error);
        CHECK_THROWS_WITH_AS(p->at("y").at(0), expected_y.c_str(), json::type_error);
    }
}
