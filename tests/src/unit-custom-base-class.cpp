//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include <algorithm>
#include <set>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

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
    SECTION("member swap")
    {
        using json = json_with_metadata<int>;
        json a = 1;
        a.metadata() = 100;
        json b = 2;
        b.metadata() = 200;

        a.swap(b);

        CHECK(a.get<int>()  == 2);
        CHECK(b.get<int>()  == 1);
        CHECK(a.metadata()  == 200);
        CHECK(b.metadata()  == 100);
    }
    SECTION("nonmember swap")
    {
        using json = json_with_metadata<int>;
        json a = 1;
        a.metadata() = 100;
        json b = 2;
        b.metadata() = 200;

        using std::swap;
        swap(a, b);

        CHECK(a.get<int>()  == 2);
        CHECK(b.get<int>()  == 1);
        CHECK(a.metadata()  == 200);
        CHECK(b.metadata()  == 100);
    }
    SECTION("std::swap")
    {
        using json = json_with_metadata<int>;
        json a = 1;
        a.metadata() = 100;
        json b = 2;
        b.metadata() = 200;

        std::swap(a, b);

        CHECK(a.get<int>()  == 2);
        CHECK(b.get<int>()  == 1);
        CHECK(a.metadata()  == 200);
        CHECK(b.metadata()  == 100);
    }
    SECTION("std::sort keeps metadata attached to its value")
    {
        // std::sort mixes swap() with moves; each value's metadata must
        // travel with it, just as it does for copy, move, and assignment
        using json = json_with_metadata<int>;
        std::vector<json> values;
        for (const int v :
                {
                    5, 3, 9, 1, 7, 2, 8, 4, 6, 0, 15, 13, 19, 11, 17, 12, 18, 14, 16, 10,
                    25, 23, 29, 21, 27, 22, 28, 24, 26, 20, 35, 33
                })
        {
            json value = v;
            value.metadata() = v;
            values.push_back(value);
        }

        std::sort(values.begin(), values.end());

        for (const auto& value : values)
        {
            CHECK(value.metadata() == value.get<int>());
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
    const json_with_visitor_t& json = *static_cast<const json_with_visitor_t*>(this); // NOLINT(cppcoreguidelines-pro-type-static-cast-downcast)
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

// Test accessing members of a custom base class that are hidden by members of nlohmann::basic_json
class base_class_with_hidden_members
{
  public:
    const char* type_name() const noexcept // NOLINT(readability-convert-member-functions-to-static)
    {
        return "custom type_name";
    }

    std::size_t size() const noexcept
    {
        return m_size;
    }

    std::size_t m_size = 42;
};

using json_with_hidden_base_members =
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
    base_class_with_hidden_members
    >;

TEST_CASE("JSON Node as_base_class")
{
    using json = json_with_hidden_base_members;

    static_assert(std::is_same<decltype(std::declval<json&>().as_base_class()), json::json_base_class_t&>::value, "");
    static_assert(std::is_same<decltype(std::declval<const json&>().as_base_class()), const json::json_base_class_t&>::value, "");
    static_assert(noexcept(std::declval<json&>().as_base_class()), "");
    static_assert(noexcept(std::declval<const json&>().as_base_class()), "");

    SECTION("non-const")
    {
        json j = {1, 2, 3};

        CHECK(std::string(j.type_name()) == "array");
        CHECK(j.size() == 3);
        CHECK(std::string(j.as_base_class().type_name()) == "custom type_name");
        CHECK(j.as_base_class().size() == 42);
        CHECK(&j.as_base_class() == &static_cast<json::json_base_class_t&>(j));

        j.as_base_class().m_size = 7;
        CHECK(j.as_base_class().size() == 7);
        CHECK(j.size() == 3);
    }

    SECTION("const")
    {
        const json j = {1, 2, 3};

        CHECK(std::string(j.type_name()) == "array");
        CHECK(j.size() == 3);
        CHECK(std::string(j.as_base_class().type_name()) == "custom type_name");
        CHECK(j.as_base_class().size() == 42);
        CHECK(&j.as_base_class() == &static_cast<const json::json_base_class_t&>(j));
    }
}

// A custom base class with a const member: copy-constructible (initializing a
// const member works fine), but not copy-/move-assignable (assigning one does
// not). Used to check that copy construction never requires more than that.
struct const_member_base
{
    const int id = 7; // NOLINT(misc-non-private-member-variables-in-classes)
};

using json_with_const_base = nlohmann::basic_json <
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
                             const_member_base
                             >;

// build an array nested @a depth levels deep, with the innermost value 1;
// every level is constructed (never assigned), since const_member_base does
// not support assignment
static json_with_const_base make_nested_array(std::size_t depth)
{
    if (depth == 0)
    {
        return json_with_const_base(1); // NOLINT(modernize-return-braced-init-list): {1} would be an array
    }
    return json_with_const_base::array({make_nested_array(depth - 1)});
}

TEST_CASE("Regression test for issue #5674 - copy construction must not require an assignable base class")
{
    SECTION("depth 0")
    {
        // as in the original bug report: copy construction only, no assignment
        const json_with_const_base j = {1, 2};
        const json_with_const_base copy = j; // NOLINT(performance-unnecessary-copy-initialization)

        CHECK(copy.size() == 2);
        CHECK(copy.id == 7);
    }

    SECTION("nested deeper than the copy constructor's descent bound")
    {
        // beyond nesting_depth_limit() (128) levels, the copy constructor
        // copies without the call stack (copy_iteratively / copy_array_level),
        // which used to assign the base class of every element it created
        const std::size_t depth = 300;

        const json_with_const_base j = make_nested_array(depth);
        const json_with_const_base copy = j; // NOLINT(performance-unnecessary-copy-initialization)

        const json_with_const_base* c = &copy;
        for (std::size_t level = 0; level <= depth; ++level)
        {
            CAPTURE(level)
            REQUIRE(c->id == 7);
            if (level < depth)
            {
                c = &c->at(0);
            }
        }
        CHECK(*c == 1);
    }
}
