/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.1.2
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

#include "catch.hpp"

#include <nlohmann/json.hpp>
#include <string>
#include <utility>

/*
 * This is virtually a string class.
 * It covers std::string under the hood.
 */
class alt_string
{
  public:
    using value_type = std::string::value_type;

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
    bool operator==(op_type&& op) const
    {
        return str_impl == op;
    }

    template <typename op_type>
    bool operator!=(op_type&& op) const
    {
        return str_impl != op;
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
    bool operator<(op_type&& op) const
    {
        return str_impl < op;
    }

    bool operator<(const alt_string& op) const
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

    const value_type* data()
    {
        return str_impl.data();
    }

  private:
    std::string str_impl;
};


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
            doc["list"] = { 1, 0, 2 };
            alt_string dump = doc.dump();
            CHECK(dump == R"({"list":[1,0,2]})");
        }
    }

    SECTION("parse")
    {
        auto doc = alt_json::parse("{\"foo\": \"bar\"}");
        alt_string dump = doc.dump();
        CHECK(dump == R"({"foo":"bar"})");
    }
}
