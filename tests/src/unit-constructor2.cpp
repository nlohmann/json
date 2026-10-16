//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <string>
#include <vector>

#include <nlohmann/json.hpp>
using nlohmann::json;

TEST_CASE("other constructors and destructor")
{
    SECTION("copy constructor")
    {
        SECTION("object")
        {
            const json j {{"foo", 1}, {"bar", false}};
            json k(j); // NOLINT(performance-unnecessary-copy-initialization)
            CHECK(j == k);
        }

        SECTION("array")
        {
            const json j {"foo", 1, 42.23, false};
            json k(j); // NOLINT(performance-unnecessary-copy-initialization)
            CHECK(j == k);
        }

        SECTION("null")
        {
            const json j(nullptr);
            json k(j); // NOLINT(performance-unnecessary-copy-initialization)
            CHECK(j == k);
        }

        SECTION("boolean")
        {
            const json j(true);
            json k(j); // NOLINT(performance-unnecessary-copy-initialization)
            CHECK(j == k);
        }

        SECTION("string")
        {
            const json j("Hello world");
            json k(j); // NOLINT(performance-unnecessary-copy-initialization)
            CHECK(j == k);
        }

        SECTION("number (integer)")
        {
            const json j(42);
            json k(j); // NOLINT(performance-unnecessary-copy-initialization)
            CHECK(j == k);
        }

        SECTION("number (unsigned)")
        {
            const  json j(42u);
            json k(j); // NOLINT(performance-unnecessary-copy-initialization)
            CHECK(j == k);
        }

        SECTION("number (floating-point)")
        {
            const json j(42.23);
            json k(j); // NOLINT(performance-unnecessary-copy-initialization)
            CHECK(j == k);
        }

        SECTION("binary")
        {
            const json j = json::binary({1, 2, 3});
            json k(j); // NOLINT(performance-unnecessary-copy-initialization)
            CHECK(j == k);
        }
    }

    SECTION("move constructor")
    {
        json j {{"foo", "bar"}, {"baz", {1, 2, 3, 4}}, {"a", 42u}, {"b", 42.23}, {"c", nullptr}};
        CHECK(j.type() == json::value_t::object);
        const json k(std::move(j));
        CHECK(k.type() == json::value_t::object);
        CHECK(j.type() == json::value_t::null); // NOLINT(bugprone-use-after-move,hicpp-invalid-access-moved,clang-analyzer-cplusplus.Move) access after move is OK here
    }

    SECTION("copy assignment")
    {
        SECTION("object")
        {
            const json j {{"foo", 1}, {"bar", false}};
            json k;
            k = j;
            CHECK(j == k);
        }

        SECTION("array")
        {
            const json j {"foo", 1, 42.23, false};
            json k;
            k = j;
            CHECK(j == k);
        }

        SECTION("null")
        {
            const json j(nullptr);
            json k;
            k = j;
            CHECK(j == k);
        }

        SECTION("boolean")
        {
            const json j(true);
            json k;
            k = j;
            CHECK(j == k);
        }

        SECTION("string")
        {
            const json j("Hello world");
            json k;
            k = j;
            CHECK(j == k);
        }

        SECTION("number (integer)")
        {
            const json j(42);
            json k;
            k = j;
            CHECK(j == k);
        }

        SECTION("number (unsigned)")
        {
            const json j(42u);
            json k;
            k = j;
            CHECK(j == k);
        }

        SECTION("number (floating-point)")
        {
            const json j(42.23);
            json k;
            k = j;
            CHECK(j == k);
        }

        SECTION("binary")
        {
            const json j = json::binary({1, 2, 3});
            json k;
            k = j;
            CHECK(j == k);
        }
    }

    SECTION("destructor")
    {
        SECTION("object")
        {
            auto* j = new json {{"foo", 1}, {"bar", false}}; // NOLINT(cppcoreguidelines-owning-memory)
            delete j; // NOLINT(cppcoreguidelines-owning-memory)
        }

        SECTION("array")
        {
            auto* j = new json {"foo", 1, 1u, false, 23.42}; // NOLINT(cppcoreguidelines-owning-memory)
            delete j; // NOLINT(cppcoreguidelines-owning-memory)
        }

        SECTION("string")
        {
            auto* j = new json("Hello world"); // NOLINT(cppcoreguidelines-owning-memory)
            delete j; // NOLINT(cppcoreguidelines-owning-memory)
        }
    }
}

TEST_CASE("copy constructor and destructor across value types")
{
    SECTION("copy of a scalar is independent of the source")
    {
        const json src_null = nullptr;
        const json src_bool = true;
        const json src_int = -7;
        const json src_uint = 7u;
        const json src_float = 2.5;

        json c_null(src_null); // NOLINT(performance-unnecessary-copy-initialization): tests the copy constructor
        json c_bool(src_bool); // NOLINT(performance-unnecessary-copy-initialization): tests the copy constructor
        json c_int(src_int); // NOLINT(performance-unnecessary-copy-initialization): tests the copy constructor
        json c_uint(src_uint); // NOLINT(performance-unnecessary-copy-initialization): tests the copy constructor
        json c_float(src_float); // NOLINT(performance-unnecessary-copy-initialization): tests the copy constructor

        CHECK(c_null.is_null());
        CHECK(c_bool == true);
        CHECK(c_int == -7);
        CHECK(c_uint == 7u);
        CHECK(c_float == 2.5);

        c_int = 8;
        c_float = 3.5;
        CHECK(src_int == -7);
        CHECK(src_float == 2.5);
    }

    SECTION("copy of an owning value, then mutate the copy")
    {
        const json src_string = "hello";
        const json src_array = {1, 2, 3};
        const json src_object = {{"a", 1}, {"b", {{"c", 2}}}};
        const json src_binary = json::binary({1, 2, 3});

        json c_string(src_string);
        json c_array(src_array);
        json c_object(src_object);
        json c_binary(src_binary);

        CHECK(c_string == src_string);
        CHECK(c_array == src_array);
        CHECK(c_object == src_object);
        CHECK(c_binary == src_binary);

        c_string.get_ref<json::string_t&>() += " world";
        c_array.push_back(4);
        c_object["b"]["c"] = 3;
        c_object["d"] = 4;
        c_binary.get_binary().push_back(4);

        CHECK(src_string == "hello");
        CHECK(src_array.size() == 3);
        CHECK(src_object["b"]["c"] == 2);
        CHECK_FALSE(src_object.contains("d"));
        CHECK(src_binary.get_binary().size() == 3);

        CHECK(c_string == "hello world");
        CHECK(c_array.size() == 4);
        CHECK(c_object["b"]["c"] == 3);
        CHECK(c_binary.get_binary().size() == 4);
    }

    SECTION("copy keeps parent pointers valid (JSON_DIAGNOSTICS)")
    {
        const json src = {{"a", {1, 2}}, {"b", "x"}};
        json c(src);
        c["a"].push_back(3);
        CHECK(c["a"].size() == 3);
        CHECK(src["a"].size() == 2);
    }

    SECTION("vector of mixed types: build, copy, and destroy")
    {
        {
            std::vector<json> v;
            for (int i = 0; i < 70; ++i)
            {
                switch (i % 9)
                {
                    case 0:
                        v.emplace_back(nullptr);
                        break;
                    case 1:
                        v.emplace_back(i % 2 == 0);
                        break;
                    case 2:
                        v.emplace_back(-i);
                        break;
                    case 3:
                        v.emplace_back(static_cast<json::number_unsigned_t>(i));
                        break;
                    case 4:
                        v.emplace_back(i * 0.5);
                        break;
                    case 5:
                        v.emplace_back(std::string(static_cast<std::size_t>(i), 'x'));
                        break;
                    case 6:
                        v.emplace_back(json::array({i, "s", nullptr}));
                        break;
                    case 7:
                        v.emplace_back(json::object({{"k", i}}));
                        break;
                    default:
                        v.emplace_back(json::binary({1, 2, 3}));
                        break;
                }
            }
            REQUIRE(v.size() == 70);

            std::vector<json> copy(v);
            CHECK((copy == v));

            // mutating the copy leaves the original alone
            copy[5] = "changed";
            copy[6].push_back(1);
            CHECK((copy != v));
            CHECK(v[5] == std::string(5, 'x'));
            CHECK(v[6].size() == 3);

            v.erase(v.begin(), v.begin() + 10);
            CHECK(v.size() == 60);
        }

        // destroying the discarded and default-constructed values
        std::vector<json> w(4);
        w.emplace_back(json::value_t::discarded);
        w.emplace_back(json::value_t::object);
        w.emplace_back(json::value_t::array);
        w.emplace_back(json::value_t::string);
        w.emplace_back(json::value_t::binary);
        CHECK(w.size() == 9);
    }
}

TEST_CASE_TEMPLATE("destructor of nested containers", Json, nlohmann::json, nlohmann::ordered_json)
{
    SECTION("empty containers")
    {
        {
            Json j = Json::array();
        }
        {
            Json j = Json::object();
        }
        {
            Json j = Json::array({Json::array(), Json::object(), Json::array({Json::array()})});
        }
    }

    SECTION("leaves mixed with nested containers")
    {
        Json j = Json::object();
        j["leaf"] = 1;
        j["str"] = "text";
        j["empty_a"] = Json::array();
        j["empty_o"] = Json::object();
        j["arr"] = Json::array({1, "a", Json::array({1, 2}), Json::object({{"k", Json::array({Json::object()})}}), nullptr});
        j["obj"] = Json::object({{"x", Json::object({{"y", Json::array({1, Json::object({{"z", 1}})})}})}, {"w", 2}});
        Json copy = j;
        CHECK(copy == j);
        j = Json::array({std::move(copy), j, 3, Json::array()});
    }

    SECTION("deep nesting")
    {
        for (int kind = 0; kind < 3; ++kind)
        {
            Json j = 1;
            for (int i = 0; i < 5000; ++i)
            {
                switch (kind)
                {
                    case 0:
                        j = Json::array({std::move(j)});
                        break;
                    case 1:
                        j = Json::object({{"k", std::move(j)}});
                        break;
                    default:
                        // siblings next to the nested child
                        j = (i % 2 == 0) ? Json::array({1, Json::array(), std::move(j)}) : Json::object({{"a", 1}, {"b", Json::object()}, {"c", std::move(j)}});
                        break;
                }
            }
        }
    }
}
