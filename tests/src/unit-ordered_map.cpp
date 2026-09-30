//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::ordered_map;

#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

// The EDG front end (Intel icpc, NVIDIA nvc++) considers the defaulted move
// constructor of std::pair<const Key, T> noexcept even if copying Key can
// throw. std::vector then moves such elements itself when it grows (and calls
// std::terminate if a key copy throws), so ordered_map leaves growing to it.
#if defined(__EDG__)
    #define JSON_TEST_PAIR_MOVE_IS_NOEXCEPT
#endif

namespace
{
// number of copies made of counted values
int value_copies = 0;

// a mapped type that counts its copies; moving from it leaves -1 behind
struct counted // NOLINT(cppcoreguidelines-special-member-functions,hicpp-special-member-functions)
{
    int payload = 0;

    counted() = default;
    explicit counted(int p) noexcept : payload(p) {}
    counted(const counted& other) : payload(other.payload)
    {
        ++value_copies;
    }
    counted(counted&& other) noexcept : payload(other.payload)
    {
        other.payload = -1;
    }
    counted& operator=(const counted&) = delete;
    counted& operator=(counted&& other) noexcept
    {
        payload = other.payload;
        other.payload = -1;
        return *this;
    }
};

#if !defined(JSON_NOEXCEPTION) && !defined(JSON_TEST_PAIR_MOVE_IS_NOEXCEPT)
// number of throwing_key copies that still succeed; the next one throws
// (a negative value means that copies never throw)
int key_copies_until_throw = -1;

// a key type whose copy constructor can be made to throw
struct throwing_key // NOLINT(cppcoreguidelines-special-member-functions,hicpp-special-member-functions)
{
    int id = 0;

    explicit throwing_key(int i) noexcept : id(i) {}
    throwing_key(const throwing_key& other) : id(other.id)
    {
        if (key_copies_until_throw == 0)
        {
            throw std::runtime_error("key copy failed");
        }
        if (key_copies_until_throw > 0)
        {
            --key_copies_until_throw;
        }
    }
    throwing_key& operator=(const throwing_key&) = delete;

    friend bool operator==(const throwing_key& lhs, const throwing_key& rhs) noexcept
    {
        return lhs.id == rhs.id;
    }
};
#endif

// a mapped type that cannot be default-constructed
struct no_default
{
    explicit no_default(int v) noexcept : value(v) {}
    int value;
};

// ordered_json must keep moving its values when an object grows
using ordered_object_t = nlohmann::ordered_json::object_t;
#if !defined(JSON_TEST_PAIR_MOVE_IS_NOEXCEPT)
    static_assert(!std::is_nothrow_move_constructible<ordered_object_t::value_type>::value, "std::vector would move the elements itself");
#endif
static_assert(std::is_copy_constructible<ordered_object_t::key_type>::value, "keys must be copyable");
static_assert(std::is_default_constructible<ordered_object_t::mapped_type>::value, "values must be default-constructible");
static_assert(std::is_nothrow_move_assignable<ordered_object_t::mapped_type>::value, "values must be nothrow move-assignable");
} // namespace

TEST_CASE("ordered_map")
{
    SECTION("constructor")
    {
        SECTION("constructor from iterator range")
        {
            std::map<std::string, std::string> m {{"eins", "one"}, {"zwei", "two"}, {"drei", "three"}};
            ordered_map<std::string, std::string> const om(m.begin(), m.end());
            CHECK(om.size() == 3);
        }

        SECTION("copy assignment")
        {
            std::map<std::string, std::string> m {{"eins", "one"}, {"zwei", "two"}, {"drei", "three"}};
            ordered_map<std::string, std::string> om(m.begin(), m.end());
            const auto com = om;
            om.clear(); // silence a warning by forbidding having "const auto& com = om;"
            CHECK(com.size() == 3);
        }
    }

    SECTION("at")
    {
        std::map<std::string, std::string> m {{"eins", "one"}, {"zwei", "two"}, {"drei", "three"}};
        ordered_map<std::string, std::string> om(m.begin(), m.end());
        const auto com = om; // NOLINT(performance-unnecessary-copy-initialization)

        SECTION("with Key&&")
        {
            CHECK(om.at(std::string("eins")) == std::string("one"));
            CHECK(com.at(std::string("eins")) == std::string("one"));
            CHECK_THROWS_AS(om.at(std::string("vier")), std::out_of_range);
            CHECK_THROWS_AS(com.at(std::string("vier")), std::out_of_range);
        }

        SECTION("with const Key&&")
        {
            const std::string eins = "eins";
            const std::string vier = "vier";
            CHECK(om.at(eins) == std::string("one"));
            CHECK(com.at(eins) == std::string("one"));
            CHECK_THROWS_AS(om.at(vier), std::out_of_range);
            CHECK_THROWS_AS(com.at(vier), std::out_of_range);
        }

        SECTION("with string literal")
        {
            CHECK(om.at("eins") == std::string("one"));
            CHECK(com.at("eins") == std::string("one"));
            CHECK_THROWS_AS(om.at("vier"), std::out_of_range);
            CHECK_THROWS_AS(com.at("vier"), std::out_of_range);
        }
    }

    SECTION("operator[]")
    {
        std::map<std::string, std::string> m {{"eins", "one"}, {"zwei", "two"}, {"drei", "three"}};
        ordered_map<std::string, std::string> om(m.begin(), m.end());
        const auto com = om; // NOLINT(performance-unnecessary-copy-initialization)

        SECTION("with Key&&")
        {
            CHECK(om[std::string("eins")] == std::string("one"));
            CHECK(com[std::string("eins")] == std::string("one"));

            CHECK(om[std::string("vier")] == std::string(""));
            CHECK(om.size() == 4);
        }

        SECTION("with const Key&&")
        {
            const std::string eins = "eins";
            const std::string vier = "vier";

            CHECK(om[eins] == std::string("one"));
            CHECK(com[eins] == std::string("one"));

            CHECK(om[vier] == std::string(""));
            CHECK(om.size() == 4);
        }

        SECTION("with string literal")
        {
            CHECK(om["eins"] == std::string("one"));
            CHECK(com["eins"] == std::string("one"));

            CHECK(om["vier"] == std::string(""));
            CHECK(om.size() == 4);
        }
    }

    SECTION("erase")
    {
        ordered_map<std::string, std::string> om;
        om["eins"] = "one";
        om["zwei"] = "two";
        om["drei"] = "three";

        {
            auto it = om.begin();
            CHECK(it->first == "eins");
            ++it;
            CHECK(it->first == "zwei");
            ++it;
            CHECK(it->first == "drei");
            ++it;
            CHECK(it == om.end());
        }

        SECTION("with Key&&")
        {
            CHECK(om.size() == 3);
            CHECK(om.erase(std::string("eins")) == 1);
            CHECK(om.size() == 2);
            CHECK(om.erase(std::string("vier")) == 0);
            CHECK(om.size() == 2);

            auto it = om.begin();
            CHECK(it->first == "zwei");
            ++it;
            CHECK(it->first == "drei");
            ++it;
            CHECK(it == om.end());
        }

        SECTION("with const Key&&")
        {
            const std::string eins = "eins";
            const std::string vier = "vier";
            CHECK(om.size() == 3);
            CHECK(om.erase(eins) == 1);
            CHECK(om.size() == 2);
            CHECK(om.erase(vier) == 0);
            CHECK(om.size() == 2);

            auto it = om.begin();
            CHECK(it->first == "zwei");
            ++it;
            CHECK(it->first == "drei");
            ++it;
            CHECK(it == om.end());
        }

        SECTION("with string literal")
        {
            CHECK(om.size() == 3);
            CHECK(om.erase("eins") == 1);
            CHECK(om.size() == 2);
            CHECK(om.erase("vier") == 0);
            CHECK(om.size() == 2);

            auto it = om.begin();
            CHECK(it->first == "zwei");
            ++it;
            CHECK(it->first == "drei");
            ++it;
            CHECK(it == om.end());
        }

        SECTION("with iterator")
        {
            CHECK(om.size() == 3);
            CHECK(om.begin()->first == "eins");
            CHECK(std::next(om.begin(), 1)->first == "zwei");
            CHECK(std::next(om.begin(), 2)->first == "drei");

            auto it = om.erase(om.begin());
            CHECK(it->first == "zwei");
            CHECK(om.size() == 2);

            auto it2 = om.begin();
            CHECK(it2->first == "zwei");
            ++it2;
            CHECK(it2->first == "drei");
            ++it2;
            CHECK(it2 == om.end());
        }

        SECTION("with iterator pair")
        {
            SECTION("range in the middle")
            {
                // need more elements
                om["vier"] = "four";
                om["fünf"] = "five";

                // delete "zwei" and "drei"
                auto it = om.erase(om.begin() + 1, om.begin() + 3);
                CHECK(it->first == "vier");
                CHECK(om.size() == 3);
            }

            SECTION("range at the beginning")
            {
                // need more elements
                om["vier"] = "four";
                om["fünf"] = "five";

                // delete "eins" and "zwei"
                auto it = om.erase(om.begin(), om.begin() + 2);
                CHECK(it->first == "drei");
                CHECK(om.size() == 3);
            }

            SECTION("range at the end")
            {
                // need more elements
                om["vier"] = "four";
                om["fünf"] = "five";

                // delete "vier" and "fünf"
                auto it = om.erase(om.begin() + 3, om.end());
                CHECK(it == om.end());
                CHECK(om.size() == 3);
            }
        }
    }

    SECTION("count")
    {
        ordered_map<std::string, std::string> om;
        om["eins"] = "one";
        om["zwei"] = "two";
        om["drei"] = "three";

        const std::string eins("eins");
        const std::string vier("vier");
        CHECK(om.count("eins") == 1);
        CHECK(om.count(std::string("eins")) == 1);
        CHECK(om.count(eins) == 1);
        CHECK(om.count("vier") == 0);
        CHECK(om.count(std::string("vier")) == 0);
        CHECK(om.count(vier) == 0);
    }

    SECTION("find")
    {
        ordered_map<std::string, std::string> om;
        om["eins"] = "one";
        om["zwei"] = "two";
        om["drei"] = "three";
        const auto com = om;

        const std::string eins("eins");
        const std::string vier("vier");
        CHECK(om.find("eins") == om.begin());
        CHECK(om.find(std::string("eins")) == om.begin());
        CHECK(om.find(eins) == om.begin());
        CHECK(om.find("vier") == om.end());
        CHECK(om.find(std::string("vier")) == om.end());
        CHECK(om.find(vier) == om.end());

        CHECK(com.find("eins") == com.begin());
        CHECK(com.find(std::string("eins")) == com.begin());
        CHECK(com.find(eins) == com.begin());
        CHECK(com.find("vier") == com.end());
        CHECK(com.find(std::string("vier")) == com.end());
        CHECK(com.find(vier) == com.end());

#ifdef JSON_HAS_CPP_17
        CHECK(om.find(std::string_view("eins")) == om.begin());
        CHECK(com.find(std::string_view("eins")) == com.begin());
#endif
    }

    SECTION("insert")
    {
        ordered_map<std::string, std::string> om;
        om["eins"] = "one";
        om["zwei"] = "two";
        om["drei"] = "three";

        SECTION("const value_type&")
        {
            ordered_map<std::string, std::string>::value_type const vt1 {"eins", "1"};
            ordered_map<std::string, std::string>::value_type const vt4 {"vier", "four"};

            auto res1 = om.insert(vt1);
            CHECK(res1.first == om.begin());
            CHECK(res1.second == false);
            CHECK(om.size() == 3);

            auto res4 = om.insert(vt4);
            CHECK(res4.first == om.begin() + 3);
            CHECK(res4.second == true);
            CHECK(om.size() == 4);
        }

        SECTION("value_type&&")
        {
            auto res1 = om.insert({"eins", "1"});
            CHECK(res1.first == om.begin());
            CHECK(res1.second == false);
            CHECK(om.size() == 3);

            auto res4 = om.insert({"vier", "four"});
            CHECK(res4.first == om.begin() + 3);
            CHECK(res4.second == true);
            CHECK(om.size() == 4);
        }
    }
}

TEST_CASE("ordered_map growth")
{
    SECTION("values are moved, not copied, when the storage grows")
    {
        ordered_map<std::string, counted> om;
        std::size_t growths = 0;
        value_copies = 0;

        // inserts 100 elements with the given function and counts the growths
        const auto fill = [&om, &growths](void (*insert)(ordered_map<std::string, counted>&, int))
        {
            for (int i = 0; i < 100; ++i)
            {
                const auto old_capacity = om.capacity();
                insert(om, i);
                if (om.capacity() > old_capacity)
                {
                    ++growths;
                }
            }
        };

        // checks that the elements are in insertion order with their values
        const auto check_contents = [&om]
        {
            CHECK(om.size() == 100);
            int i = 0;
            for (const auto& element : om)
            {
                CHECK(element.first == std::to_string(i));
                CHECK(element.second.payload == i);
                ++i;
            }
        };

        SECTION("emplace")
        {
            fill([](ordered_map<std::string, counted>& m, int i)
            {
                m.emplace(std::to_string(i), counted(i));
            });
            CHECK(growths >= 3);
            CHECK(value_copies == 0);
            check_contents();
        }

        SECTION("operator[]")
        {
            fill([](ordered_map<std::string, counted>& m, int i)
            {
                m[std::to_string(i)] = counted(i);
            });
            CHECK(growths >= 3);
            CHECK(value_copies == 0);
            check_contents();
        }

        SECTION("insert(value_type&&)")
        {
            fill([](ordered_map<std::string, counted>& m, int i)
            {
                m.insert({std::to_string(i), counted(i)});
            });
            CHECK(growths >= 3);
            CHECK(value_copies == 0);
            check_contents();
        }

        SECTION("insert(const value_type&)")
        {
            fill([](ordered_map<std::string, counted>& m, int i)
            {
                const std::pair<const std::string, counted> value(std::to_string(i), counted(i));
                m.insert(value);
            });
            CHECK(growths >= 3);
            // only the inserted values are copied
            CHECK(value_copies == 100);
            check_contents();
        }

        SECTION("insert(first, last)")
        {
            std::vector<std::pair<const std::string, counted>> values;
            values.reserve(100);
            for (int i = 0; i < 100; ++i)
            {
                values.emplace_back(std::to_string(i), counted(i));
            }
            value_copies = 0;

            om.insert(values.cbegin(), values.cend());
            // only the inserted values are copied
            CHECK(value_copies == 100);
            check_contents();
        }
    }

    SECTION("elements keep their order and values over many growths")
    {
        ordered_map<std::string, counted> om;
        for (int i = 0; i < 1000; ++i)
        {
            om.emplace(std::to_string(i), counted(i));
        }

        CHECK(om.size() == 1000);
        int i = 0;
        for (const auto& element : om)
        {
            CHECK(element.first == std::to_string(i));
            CHECK(element.second.payload == i);
            ++i;
        }
    }

    SECTION("arguments may refer to elements of the full container")
    {
        SECTION("moving a value out of the container")
        {
            ordered_map<std::string, counted> om;
            om.reserve(4);
            while (om.size() < om.capacity())
            {
                const auto i = static_cast<int>(om.size());
                om.emplace(std::to_string(i), counted(i));
            }
            const auto size = om.size();

            om.emplace("new", std::move(om.at("0")));
            CHECK(om.size() == size + 1);
            CHECK(om.at("new").payload == 0);
            CHECK(om.at("0").payload == -1);
        }

        SECTION("using a value as key")
        {
            ordered_map<std::string, std::string> om;
            om.reserve(4);
            while (om.size() < om.capacity())
            {
                const auto i = std::to_string(om.size());
                om.emplace("k" + i, "v" + i);
            }
            const auto size = om.size();

            om.emplace(om.at("k0"), std::string("x"));
            CHECK(om.size() == size + 1);
            CHECK(om.at("k0") == "v0");
            CHECK(om.at("v0") == "x");
        }

        SECTION("ordered_json")
        {
            auto j = nlohmann::ordered_json::object();
            auto& object = j.get_ref<nlohmann::ordered_json::object_t&>();
            object.reserve(4);
            while (object.size() < object.capacity())
            {
                const auto i = std::to_string(object.size());
                j[i] = "a value that is too long for the small string optimization " + i;
            }
            const auto size = j.size();

            j.emplace("new", std::move(j["0"]));
            CHECK(j.size() == size + 1);
            CHECK(j["new"] == "a value that is too long for the small string optimization 0");
            CHECK(j["0"].is_null());
        }
    }

#if !defined(JSON_NOEXCEPTION) && !defined(JSON_TEST_PAIR_MOVE_IS_NOEXCEPT)
    SECTION("the container is unchanged if growing it throws")
    {
        ordered_map<throwing_key, counted> om;
        om.reserve(4);
        while (om.size() < om.capacity())
        {
            const auto i = static_cast<int>(om.size());
            om.emplace(throwing_key(i), counted(i));
        }
        const auto size = om.size();
        const auto capacity = om.capacity();

        // checks that the elements are unchanged
        const auto check_unchanged = [&om, size, capacity]
        {
            CHECK(om.size() == size);
            CHECK(om.capacity() == capacity);
            int i = 0;
            for (const auto& element : om)
            {
                CHECK(element.first.id == i);
                CHECK(element.second.payload == i);
                ++i;
            }
        };

        SECTION("emplace")
        {
            // growing copies the existing keys and then the new one; let each of these copies throw
            for (std::size_t k = 0; k <= size; ++k)
            {
                counted value(100);
                key_copies_until_throw = static_cast<int>(k);
                CHECK_THROWS_AS(om.emplace(throwing_key(100), std::move(value)), std::runtime_error);
                key_copies_until_throw = -1;

                check_unchanged();
                CHECK(value.payload == 100); // NOLINT(bugprone-use-after-move,hicpp-invalid-access-moved)
            }

            om.emplace(throwing_key(100), counted(100));
            CHECK(om.size() == size + 1);
            CHECK(om.capacity() > capacity);
            CHECK(om.at(throwing_key(100)).payload == 100);
        }

        SECTION("insert(const value_type&)")
        {
            const std::pair<const throwing_key, counted> value(throwing_key(100), counted(100));
            value_copies = 0;

            key_copies_until_throw = static_cast<int>(size / 2);
            CHECK_THROWS_AS(om.insert(value), std::runtime_error);
            key_copies_until_throw = -1;

            check_unchanged();
            CHECK(value_copies == 0);
        }
    }
#endif

    SECTION("elements that std::vector moves, or that cannot be moved back")
    {
        SECTION("nothrow move-constructible elements")
        {
            ordered_map<int, counted> om;
            value_copies = 0;
            for (int i = 0; i < 100; ++i)
            {
                om.emplace(i, counted(i));
            }
            CHECK(om.size() == 100);
            CHECK(value_copies == 0);
        }

        SECTION("mapped type without default constructor")
        {
            ordered_map<std::string, no_default> om;
            for (int i = 0; i < 100; ++i)
            {
                om.emplace(std::to_string(i), no_default(i));
            }

            CHECK(om.size() == 100);
            int i = 0;
            for (const auto& element : om)
            {
                CHECK(element.first == std::to_string(i));
                CHECK(element.second.value == i);
                ++i;
            }
        }
    }
}
