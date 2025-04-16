//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013 - 2025 Niels Lohmann <https://nlohmann.me>
// SPDX-FileCopyrightText: 2018 Vitaliy Manushkin <agri@akamo.info>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>

#include <string>
#include <utility>

/* forward declarations */
class alt_string;
bool operator<(const char* op1, const alt_string& op2) noexcept; // NOLINT(misc-use-internal-linkage)
void int_to_string(alt_string& target, std::size_t value); // NOLINT(misc-use-internal-linkage)

/*
 * This is virtually a string class.
 * It covers std::string under the hood.
 */
class alt_string
{
  public:
    using value_type = std::string::value_type;

    static constexpr auto npos = (std::numeric_limits<std::size_t>::max)();

    alt_string(const char* str): str_impl(str) {}
    alt_string(const char* str, std::size_t count): str_impl(str, count) {}
    alt_string(size_t count, char chr): str_impl(count, chr) {}
    alt_string() = default;

    alt_string& append(char ch)
    {
        str_impl.push_back(ch);
        return *this;
    }

    alt_string& append(const alt_string& str)
    {
        str_impl.append(str.str_impl);
        return *this;
    }

    alt_string& append(const char* s, std::size_t length)
    {
        str_impl.append(s, length);
        return *this;
    }

    void push_back(char c)
    {
        str_impl.push_back(c);
    }

    template <typename op_type>
    bool operator==(const op_type& op) const
    {
        return str_impl == op;
    }

    bool operator==(const alt_string& op) const
    {
        return str_impl == op.str_impl;
    }

    template <typename op_type>
    bool operator!=(const op_type& op) const
    {
        return str_impl != op;
    }

    bool operator!=(const alt_string& op) const
    {
        return str_impl != op.str_impl;
    }

    std::size_t size() const noexcept
    {
        return str_impl.size();
    }

    void resize (std::size_t n)
    {
        str_impl.resize(n);
    }

    void resize (std::size_t n, char c)
    {
        str_impl.resize(n, c);
    }

    template <typename op_type>
    bool operator<(const op_type& op) const noexcept
    {
        return str_impl < op;
    }

    bool operator<(const alt_string& op) const noexcept
    {
        return str_impl < op.str_impl;
    }

    const char* c_str() const
    {
        return str_impl.c_str();
    }

    char& operator[](std::size_t index)
    {
        return str_impl[index];
    }

    const char& operator[](std::size_t index) const
    {
        return str_impl[index];
    }

    char& back()
    {
        return str_impl.back();
    }

    const char& back() const
    {
        return str_impl.back();
    }

    void clear()
    {
        str_impl.clear();
    }

    const value_type* data() const
    {
        return str_impl.data();
    }

    bool empty() const
    {
        return str_impl.empty();
    }

    std::size_t find(const alt_string& str, std::size_t pos = 0) const
    {
        return str_impl.find(str.str_impl, pos);
    }

    std::size_t find_first_of(char c, std::size_t pos = 0) const
    {
        return str_impl.find_first_of(c, pos);
    }

    alt_string substr(std::size_t pos = 0, std::size_t count = npos) const
    {
        const std::string s = str_impl.substr(pos, count);
        return {s.data(), s.size()};
    }

    alt_string& replace(std::size_t pos, std::size_t count, const alt_string& str)
    {
        str_impl.replace(pos, count, str.str_impl);
        return *this;
    }

    void reserve( std::size_t new_cap = 0 )
    {
        str_impl.reserve(new_cap);
    }

  private:
    std::string str_impl {}; // NOLINT(readability-redundant-member-init)

    friend bool operator<(const char* /*op1*/, const alt_string& /*op2*/) noexcept;
};

void int_to_string(alt_string& target, std::size_t value)
{
    target = std::to_string(value).c_str();
}

using alt_json = nlohmann::basic_json <
                 std::map,
                 std::vector,
                 alt_string,
                 bool,
                 std::int64_t,
                 std::uint64_t,
                 double,
                 std::allocator,
                 nlohmann::adl_serializer >;

bool operator<(const char* op1, const alt_string& op2) noexcept
{
    return op1 < op2.str_impl;
}

TEST_CASE("alternative string type")
{
    SECTION("dump")
    {
        {
            alt_json doc;
            doc["pi"] = 3.141;
            alt_string dump = doc.dump();
            CHECK(dump == R"({"pi":3.141})");
        }

        {
            alt_json doc;
            doc["happy"] = true;
            alt_string dump = doc.dump();
            CHECK(dump == R"({"happy":true})");
        }

        {
            alt_json doc;
            doc["name"] = "I'm Batman";
            alt_string dump = doc.dump();
            CHECK(dump == R"({"name":"I'm Batman"})");
        }

        {
            alt_json doc;
            doc["nothing"] = nullptr;
            alt_string dump = doc.dump();
            CHECK(dump == R"({"nothing":null})");
        }

        {
            alt_json doc;
            doc["answer"]["everything"] = 42;
            alt_string dump = doc.dump();
            CHECK(dump == R"({"answer":{"everything":42}})");
        }

        {
            alt_json doc;
            doc["list"] = { 1, 0, 2 };
            alt_string dump = doc.dump();
            CHECK(dump == R"({"list":[1,0,2]})");
        }

        {
            alt_json doc;
            doc["object"] = { {"currency", "USD"}, {"value", 42.99} };
            alt_string dump = doc.dump();
            CHECK(dump == R"({"object":{"currency":"USD","value":42.99}})");
        }
    }

    SECTION("parse")
    {
        auto doc = alt_json::parse(R"({"foo": "bar"})");
        alt_string dump = doc.dump();
        CHECK(dump == R"({"foo":"bar"})");
    }

    SECTION("items")
    {
        auto doc = alt_json::parse(R"({"foo": "bar"})");

        for (const auto& item : doc.items())
        {
            CHECK(item.key() == "foo");
            CHECK(item.value() == "bar");
        }

        auto doc_array = alt_json::parse(R"(["foo", "bar"])");

        for (const auto& item : doc_array.items())
        {
            if (item.key() == "0" )
            {
                CHECK( item.value() == "foo" );
            }
            else if (item.key() == "1" )
            {
                CHECK(item.value() == "bar");
            }
            else
            {
                CHECK(false);
            }
        }
    }

    SECTION("equality")
    {
        alt_json doc;
        doc["Who are you?"] = "I'm Batman";

        CHECK("I'm Batman" == doc["Who are you?"]);
        CHECK(doc["Who are you?"]  == "I'm Batman");
        CHECK_FALSE("I'm Batman" != doc["Who are you?"]);
        CHECK_FALSE(doc["Who are you?"]  != "I'm Batman");

        CHECK("I'm Bruce Wayne" != doc["Who are you?"]);
        CHECK(doc["Who are you?"]  != "I'm Bruce Wayne");
        CHECK_FALSE("I'm Bruce Wayne" == doc["Who are you?"]);
        CHECK_FALSE(doc["Who are you?"]  == "I'm Bruce Wayne");

        {
            const alt_json& const_doc = doc;

            CHECK("I'm Batman" == const_doc["Who are you?"]);
            CHECK(const_doc["Who are you?"] == "I'm Batman");
            CHECK_FALSE("I'm Batman" != const_doc["Who are you?"]);
            CHECK_FALSE(const_doc["Who are you?"] != "I'm Batman");

            CHECK("I'm Bruce Wayne" != const_doc["Who are you?"]);
            CHECK(const_doc["Who are you?"] != "I'm Bruce Wayne");
            CHECK_FALSE("I'm Bruce Wayne" == const_doc["Who are you?"]);
            CHECK_FALSE(const_doc["Who are you?"] == "I'm Bruce Wayne");
        }
    }

    SECTION("JSON pointer")
    {
        // conversion from json to alt_json fails to compile (see #3425);
        // attempted fix(*) produces: [[['b','a','r'],['b','a','z']]] (with each char being an integer)
        // (*) disable implicit conversion for json_refs of any basic_json type
        // alt_json j = R"(
        // {
        //     "foo": ["bar", "baz"]
        // }
        // )"_json;
        auto j = alt_json::parse(R"({"foo": ["bar", "baz"]})");

        CHECK(j.at(alt_json::json_pointer("/foo/0")) == j["foo"][0]);
        CHECK(j.at(alt_json::json_pointer("/foo/1")) == j["foo"][1]);
    }

    SECTION("patch")
    {
        alt_json const patch1 = alt_json::parse(R"([{ "op": "add", "path": "/a/b", "value": [ "foo", "bar" ] }])");
        alt_json const doc1 = alt_json::parse(R"({ "a": { "foo": 1 } })");

        CHECK_NOTHROW(doc1.patch(patch1));
        alt_json doc1_ans = alt_json::parse(R"(
                                            {
                                                "a": {
                                                    "foo": 1,
                                                    "b": [ "foo", "bar" ]
                                                }
                                            }
                                           )");
        CHECK(doc1.patch(patch1) == doc1_ans);
    }

    SECTION("diff")
    {
        alt_json const j1 = {"foo", "bar", "baz"};
        alt_json const j2 = {"foo", "bam"};
        CHECK(alt_json::diff(j1, j2).dump() == "[{\"op\":\"replace\",\"path\":\"/1\",\"value\":\"bam\"},{\"op\":\"remove\",\"path\":\"/2\"}]");
    }

    SECTION("flatten")
    {
        // a JSON value
        const alt_json j = alt_json::parse(R"({"foo": ["bar", "baz"]})");
        const auto j2 = j.flatten();
        CHECK(j2.dump() == R"({"/foo/0":"bar","/foo/1":"baz"})");
    }
}
