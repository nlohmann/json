/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.10.2
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
SPDX-License-Identifier: MIT
Copyright (c) 2013-2019 Niels Lohmann <http://nlohmann.me>.

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

#include <set>
#include <sstream>
#include <string>

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>

// Test extending nlohmann::json by using a custom base class.
// Add some metadata to each node and test the behaviour of copy / move
template<class MetaDataType>
class json_metadata
{
  public:
    using metadata_t = MetaDataType;
    metadata_t& metadata()
    {
        return m_metadata;
    }
    const metadata_t& metadata() const
    {
        return m_metadata;
    }
  private:
    metadata_t m_metadata = {};
};

template<class T>
using json_with_metadata =
    nlohmann::basic_json <
    std::map,
    std::vector,
    std::string,
    bool,
    std::int64_t,
    std::uint64_t,
    double,
    std::allocator,
    nlohmann::adl_serializer,
    std::vector<std::uint8_t>,
    json_metadata<T>
    >;

TEST_CASE("JSON Node Metadata")
{
    SECTION("type int")
    {
        using json = json_with_metadata<int>;
        json null;
        auto obj   = json::object();
        auto array = json::array();

        null.metadata()  = 1;
        obj.metadata()   = 2;
        array.metadata() = 3;
        auto copy = array;

        CHECK(null.metadata()  == 1);
        CHECK(obj.metadata()   == 2);
        CHECK(array.metadata() == 3);
        CHECK(copy.metadata()  == 3);
    }
    SECTION("type vector<int>")
    {
        using json = json_with_metadata<std::vector<int>>;
        json value;
        value.metadata().emplace_back(1);
        auto copy = value;
        value.metadata().emplace_back(2);

        CHECK(copy.metadata().size()  == 1);
        CHECK(copy.metadata().at(0)   == 1);
        CHECK(value.metadata().size() == 2);
        CHECK(value.metadata().at(0)  == 1);
        CHECK(value.metadata().at(1)  == 2);
    }
    SECTION("copy ctor")
    {
        using json = json_with_metadata<std::vector<int>>;
        json value;
        value.metadata().emplace_back(1);
        value.metadata().emplace_back(2);

        json copy = value;

        CHECK(copy.metadata().size()  == 2);
        CHECK(copy.metadata().at(0)   == 1);
        CHECK(copy.metadata().at(1)   == 2);
        CHECK(value.metadata().size() == 2);
        CHECK(value.metadata().at(0)  == 1);
        CHECK(value.metadata().at(1)  == 2);

        value.metadata().clear();
        CHECK(copy.metadata().size()  == 2);
        CHECK(value.metadata().size() == 0);
    }
    SECTION("move ctor")
    {
        using json = json_with_metadata<std::vector<int>>;
        json value;
        value.metadata().emplace_back(1);
        value.metadata().emplace_back(2);

        const json moved = std::move(value);

        CHECK(moved.metadata().size()  == 2);
        CHECK(moved.metadata().at(0)   == 1);
        CHECK(moved.metadata().at(1)   == 2);
    }
    SECTION("move assign")
    {
        using json = json_with_metadata<std::vector<int>>;
        json value;
        value.metadata().emplace_back(1);
        value.metadata().emplace_back(2);

        json moved;
        moved = std::move(value);

        CHECK(moved.metadata().size()  == 2);
        CHECK(moved.metadata().at(0)   == 1);
        CHECK(moved.metadata().at(1)   == 2);
    }
    SECTION("copy assign")
    {
        using json = json_with_metadata<std::vector<int>>;
        json value;
        value.metadata().emplace_back(1);
        value.metadata().emplace_back(2);

        json copy;
        copy = value;

        CHECK(copy.metadata().size()  == 2);
        CHECK(copy.metadata().at(0)   == 1);
        CHECK(copy.metadata().at(1)   == 2);
        CHECK(value.metadata().size() == 2);
        CHECK(value.metadata().at(0)  == 1);
        CHECK(value.metadata().at(1)  == 2);

        value.metadata().clear();
        CHECK(copy.metadata().size()  == 2);
        CHECK(value.metadata().size() == 0);
    }
    SECTION("type unique_ptr<int>")
    {
        using json = json_with_metadata<std::unique_ptr<int>>;
        json value;
        value.metadata().reset(new int(42)); // NOLINT(cppcoreguidelines-owning-memory)
        auto moved = std::move(value);

        CHECK(moved.metadata() != nullptr);
        CHECK(*moved.metadata() == 42);
    }
    SECTION("type vector<int> in json array")
    {
        using json = json_with_metadata<std::vector<int>>;
        json value;
        value.metadata().emplace_back(1);
        value.metadata().emplace_back(2);

        json const array(10, value);

        CHECK(value.metadata().size() == 2);
        CHECK(value.metadata().at(0)  == 1);
        CHECK(value.metadata().at(1)  == 2);

        for (const auto& val : array)
        {
            CHECK(val.metadata().size() == 2);
            CHECK(val.metadata().at(0)  == 1);
            CHECK(val.metadata().at(1)  == 2);
        }
    }
}

// Test extending nlohmann::json by using a custom base class.
// Add a custom member function template iterating over the whole json tree.
class visitor_adaptor
{
  public:
    template <class Fnc>
    void visit(const Fnc& fnc) const;
  private:
    template <class Ptr, class Fnc>
    void do_visit(const Ptr& ptr, const Fnc& fnc) const;
};

using json_with_visitor_t = nlohmann::basic_json <
                            std::map,
                            std::vector,
                            std::string,
                            bool,
                            std::int64_t,
                            std::uint64_t,
                            double,
                            std::allocator,
                            nlohmann::adl_serializer,
                            std::vector<std::uint8_t>,
                            visitor_adaptor
                            >;

template <class Fnc>
void visitor_adaptor::visit(const Fnc& fnc) const
{
    do_visit(json_with_visitor_t::json_pointer{}, fnc);
}

template <class Ptr, class Fnc>
void visitor_adaptor::do_visit(const Ptr& ptr, const Fnc& fnc) const
{
    using value_t = nlohmann::detail::value_t;
    const json_with_visitor_t& json = *static_cast<const json_with_visitor_t*>(this);
    switch (json.type())
    {
        case value_t::object:
            for (const auto& entry : json.items())
            {
                entry.value().do_visit(ptr / entry.key(), fnc);
            }
            break;
        case value_t::array:
            for (std::size_t i = 0; i < json.size(); ++i)
            {
                json.at(i).do_visit(ptr / std::to_string(i), fnc);
            }
            break;
        case value_t::discarded:
            break;
        case value_t::null:
        case value_t::string:
        case value_t::boolean:
        case value_t::number_integer:
        case value_t::number_unsigned:
        case value_t::number_float:
        case value_t::binary:
        default:
            fnc(ptr, json);
    }
}

TEST_CASE("JSON Visit Node")
{
    json_with_visitor_t json;
    json["null"];
    json["int"]  = -1;
    json["uint"] = 1U;
    json["float"] = 1.0;
    json["boolean"] = true;
    json["string"] = "string";
    json["array"].push_back(0);
    json["array"].push_back(1);
    json["array"].push_back(json);

    std::set<std::string> expected
    {
        "/null - null - null",
        "/int - number_integer - -1",
        "/uint - number_unsigned - 1",
        "/float - number_float - 1.0",
        "/boolean - boolean - true",
        "/string - string - \"string\"",
        "/array/0 - number_integer - 0",
        "/array/1 - number_integer - 1",

        "/array/2/null - null - null",
        "/array/2/int - number_integer - -1",
        "/array/2/uint - number_unsigned - 1",
        "/array/2/float - number_float - 1.0",
        "/array/2/boolean - boolean - true",
        "/array/2/string - string - \"string\"",
        "/array/2/array/0 - number_integer - 0",
        "/array/2/array/1 - number_integer - 1"
    };

    json.visit(
        [&](const json_with_visitor_t::json_pointer & p,
            const json_with_visitor_t& j)
    {
        std::stringstream str;
        str << p.to_string() << " - " ;
        using value_t = nlohmann::detail::value_t;
        switch (j.type())
        {
            case value_t::object:
                str << "object";
                break;
            case value_t::array:
                str << "array";
                break;
            case value_t::discarded:
                str << "discarded";
                break;
            case value_t::null:
                str << "null";
                break;
            case value_t::string:
                str << "string";
                break;
            case value_t::boolean:
                str << "boolean";
                break;
            case value_t::number_integer:
                str << "number_integer";
                break;
            case value_t::number_unsigned:
                str << "number_unsigned";
                break;
            case value_t::number_float:
                str << "number_float";
                break;
            case value_t::binary:
                str << "binary";
                break;
            default:
                str << "error";
                break;
        }
        str << " - "  << j.dump();
        CHECK(json.at(p) == j);
        INFO(str.str());
        CHECK(expected.count(str.str()) == 1);
        expected.erase(str.str());
    }
    );
    CHECK(expected.empty());
}
