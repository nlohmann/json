/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.10.5
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
SPDX-License-Identifier: MIT
Copyright (c) 2018 Vitaliy Manushkin <agri@akamo.info>.

Permission is hereby  granted, free of charge, to any  person obtaining a copy
of this software and associated  documentation files (the "Software"), to deal
in the Software  without restriction, including without  limitation the rights
to  use, copy,  modify, merge,  publish, distribute,  sublicense, and/or  sell
copies  of  the Software,  and  to  permit persons  to  whom  the Software  is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE  IS PROVIDED "AS  IS", WITHOUT WARRANTY  OF ANY KIND,  EXPRESS OR
IMPLIED,  INCLUDING BUT  NOT  LIMITED TO  THE  WARRANTIES OF  MERCHANTABILITY,
FITNESS FOR  A PARTICULAR PURPOSE AND  NONINFRINGEMENT. IN NO EVENT  SHALL THE
AUTHORS  OR COPYRIGHT  HOLDERS  BE  LIABLE FOR  ANY  CLAIM,  DAMAGES OR  OTHER
LIABILITY, WHETHER IN AN ACTION OF  CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE  OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <iostream>
#include <string>
#include <utility>


/* forward declarations */
class alt_string;
bool operator<(const char* op1, const alt_string& op2) noexcept;
void int_to_string(alt_string& target, std::size_t value);

/*
 * This is virtually a string class.
 * It covers std::string under the hood.
 */
class alt_string
{
  public:
    using value_type = std::string::value_type;

    static constexpr auto npos = static_cast<std::size_t>(-1);

    alt_string(const char* str): str_impl(str) {}
    alt_string(const char* str, std::size_t count): str_impl(str, count) {}
    alt_string(size_t count, char chr): str_impl(count, chr) {}
    alt_string() = default;

    template <typename...TParams>
    alt_string& append(TParams&& ...params)
    {
        str_impl.append(std::forward<TParams>(params)...);
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
        std::string s = str_impl.substr(pos, count);
        return {s.data(), s.size()};
    }

    alt_string& replace(std::size_t pos, std::size_t count, const alt_string& str)
    {
        str_impl.replace(pos, count, str.str_impl);
        return *this;
    }

  private:
    std::string str_impl {};

    friend bool ::operator<(const char* /*op1*/, const alt_string& /*op2*/) noexcept;
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
        auto j = alt_json::parse(R"({"foo": ["bar", "baz"]})");

        CHECK(j.at(alt_json::json_pointer("/foo/0")) == j["foo"][0]);
        CHECK(j.at(alt_json::json_pointer("/foo/1")) == j["foo"][1]);
    }

    SECTION("conversion (#3425)")
    {
        SECTION("string")
        {
            SECTION("json to alt_json")
            {
                json j("foo");
                alt_json aj = j;

                alt_string as = aj.dump();
                CHECK(j.is_string());
                CHECK(j.dump() == "\"foo\"");
                CHECK(j.dump() == std::string(as.data(), as.size()));
            }

            SECTION("alt_json to json")
            {
                alt_json aj("foo");
                json j = aj;

                alt_string as = aj.dump();
                CHECK(aj.is_string());
                CHECK(j.dump() == "\"foo\"");
                CHECK(j.dump() == std::string(as.data(), as.size()));
            }
        }

        SECTION("array")
        {
            SECTION("json to alt_json")
            {
                json j{"foo"};
                alt_json aj = j;

                alt_string as = aj.dump();
                CHECK(j.is_array());
                CHECK(j.dump() == "[\"foo\"]");
                CHECK(j.dump() == std::string(as.data(), as.size()));
            }

            SECTION("alt_json to json")
            {
                alt_json aj{"foo"};
                json j = aj;

                alt_string as = aj.dump();
                CHECK(aj.is_array());
                CHECK(j.dump() == "[\"foo\"]");
                CHECK(j.dump() == std::string(as.data(), as.size()));
            }
        }

        SECTION("object")
        {
            SECTION("json to alt_json")
            {
                json j{{"foo", {"bar", "baz"}}};
                alt_json aj = j;

                alt_string as = aj.dump();
                CHECK(j.is_object());
                CHECK(j.dump() == "{\"foo\":[\"bar\",\"baz\"]}");
                CHECK(j.dump() == std::string(as.data(), as.size()));
            }

            SECTION("alt_json to json")
            {
                alt_json aj{{"foo", {"bar", "baz"}}};
                json j = aj;

                alt_string as = aj.dump();
                CHECK(aj.is_object());
                CHECK(j.dump() == "{\"foo\":[\"bar\",\"baz\"]}");
                CHECK(j.dump() == std::string(as.data(), as.size()));
            }
        }

        SECTION("binary")
        {
            SECTION("json to alt_json")
            {
                auto j = json::binary({1, 2, 3, 4}, 128);
                alt_json aj = j;

                alt_string as = aj.dump();
                CHECK(j.is_binary());
                CHECK(j.dump() == "{\"bytes\":[1,2,3,4],\"subtype\":128}");
                CHECK(j.dump() == std::string(as.data(), as.size()));
            }

            SECTION("alt_json to json")
            {
                auto aj = alt_json::binary({1, 2, 3, 4}, 128);
                json j = aj;

                alt_string as = aj.dump();
                CHECK(aj.is_binary());
                CHECK(j.dump() == "{\"bytes\":[1,2,3,4],\"subtype\":128}");
                CHECK(j.dump() == std::string(as.data(), as.size()));
            }
        }
    }
}
