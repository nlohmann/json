/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 2.0.7
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
Copyright (c) 2013-2016 Niels Lohmann <http://nlohmann.me>.

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

#include <array>
#include <map>
#include <string>
#include <memory>
#include "catch.hpp"

#include "json.hpp"

using nlohmann::json;

namespace udt
{
enum class country
{
    china,
    france,
    russia
};

struct age
{
    int m_val;
};

struct name
{
    std::string m_val;
};

struct address
{
    std::string m_val;
};

struct person
{
    age m_age;
    name m_name;
    country m_country;
};

struct contact
{
    person m_person;
    address m_address;
};

struct contact_book
{
    name m_book_name;
    std::vector<contact> m_contacts;
};
}

// to_json methods
namespace udt
{
// templates because of the custom_json tests (see below)
template <typename Json>
void to_json(Json& j, age a)
{
    j = a.m_val;
}

template <typename Json>
void to_json(Json& j, name const& n)
{
    j = n.m_val;
}

template <typename Json>
void to_json(Json& j, country c)
{
    switch (c)
    {
        case country::china:
            j = u8"中华人民共和国";
            return;
        case country::france:
            j = "France";
            return;
        case country::russia:
            j = u8"Российская Федерация";
            return;
    }
}

template <typename Json>
void to_json(Json& j, person const& p)
{
    j = Json{{"age", p.m_age}, {"name", p.m_name}, {"country", p.m_country}};
}

void to_json(nlohmann::json& j, address const& a)
{
    j = a.m_val;
}

void to_json(nlohmann::json& j, contact const& c)
{
    j = json{{"person", c.m_person}, {"address", c.m_address}};
}

void to_json(nlohmann::json& j, contact_book const& cb)
{
    j = json{{"name", cb.m_book_name}, {"contacts", cb.m_contacts}};
}

// operators
bool operator==(age lhs, age rhs)
{
    return lhs.m_val == rhs.m_val;
}

bool operator==(address const& lhs, address const& rhs)
{
    return lhs.m_val == rhs.m_val;
}

bool operator==(name const& lhs, name const& rhs)
{
    return lhs.m_val == rhs.m_val;
}

bool operator==(person const& lhs, person const& rhs)
{
    return std::tie(lhs.m_name, lhs.m_age) == std::tie(rhs.m_name, rhs.m_age);
}

bool operator==(contact const& lhs, contact const& rhs)
{
    return std::tie(lhs.m_person, lhs.m_address) ==
           std::tie(rhs.m_person, rhs.m_address);
}

bool operator==(contact_book const& lhs, contact_book const& rhs)
{
    return std::tie(lhs.m_book_name, lhs.m_contacts) ==
           std::tie(rhs.m_book_name, rhs.m_contacts);
}
}

// from_json methods
namespace udt
{
template <typename Json>
void from_json(Json const& j, age& a)
{
    a.m_val = j.template get<int>();
}

template <typename Json>
void from_json(Json const& j, name& n)
{
    n.m_val = j.template get<std::string>();
}

template <typename Json>
void from_json(Json const& j, country& c)
{
    const auto str = j.template get<std::string>();
    static const std::map<std::string, country> m =
    {
        {u8"中华人民共和国", country::china},
        {"France", country::france},
        {"Российская Федерация", country::russia}
    };

    const auto it = m.find(str);
    // TODO test exceptions
    c = it->second;
}

template <typename Json>
void from_json(Json const& j, person& p)
{
    p.m_age = j["age"].template get<age>();
    p.m_name = j["name"].template get<name>();
    p.m_country = j["country"].template get<country>();
}

void from_json(nlohmann::json const& j, address& a)
{
    a.m_val = j.get<std::string>();
}

void from_json(nlohmann::json const& j, contact& c)
{
    c.m_person = j["person"].get<person>();
    c.m_address = j["address"].get<address>();
}

void from_json(nlohmann::json const& j, contact_book& cb)
{
    cb.m_book_name = j["name"].get<name>();
    cb.m_contacts = j["contacts"].get<std::vector<contact>>();
}
}

TEST_CASE("basic usage", "[udt]")
{

    // a bit narcissic maybe :) ?
    const udt::age a
    {
        23
    };
    const udt::name n{"theo"};
    const udt::country c{udt::country::france};
    const udt::person sfinae_addict{a, n, c};
    const udt::person senior_programmer{{42}, {u8"王芳"}, udt::country::china};
    const udt::address addr{"Paris"};
    const udt::contact cpp_programmer{sfinae_addict, addr};
    const udt::contact_book book{{"C++"}, {cpp_programmer, {senior_programmer, addr}}};

    SECTION("conversion to json via free-functions")
    {
        CHECK(json(a) == json(23));
        CHECK(json(n) == json("theo"));
        CHECK(json(c) == json("France"));
        CHECK(json(sfinae_addict) == R"({"name":"theo", "age":23, "country":"France"})"_json);
        CHECK(json("Paris") == json(addr));
        CHECK(json(cpp_programmer) ==
              R"({"person" : {"age":23, "name":"theo", "country":"France"}, "address":"Paris"})"_json);

        CHECK(
            json(book) ==
            u8R"({"name":"C++", "contacts" : [{"person" : {"age":23, "name":"theo", "country":"France"}, "address":"Paris"}, {"person" : {"age":42, "country":"中华人民共和国", "name":"王芳"}, "address":"Paris"}]})"_json);

    }

    SECTION("conversion from json via free-functions")
    {
        const auto big_json =
            u8R"({"name":"C++", "contacts" : [{"person" : {"age":23, "name":"theo", "country":"France"}, "address":"Paris"}, {"person" : {"age":42, "country":"中华人民共和国", "name":"王芳"}, "address":"Paris"}]})"_json;
        const auto parsed_book = big_json.get<udt::contact_book>();
        const auto book_name = big_json["name"].get<udt::name>();
        const auto contacts = big_json["contacts"].get<std::vector<udt::contact>>();
        const auto contact_json = big_json["contacts"].at(0);
        const auto contact = contact_json.get<udt::contact>();
        const auto person = contact_json["person"].get<udt::person>();
        const auto address = contact_json["address"].get<udt::address>();
        const auto age = contact_json["person"]["age"].get<udt::age>();
        const auto country = contact_json["person"]["country"].get<udt::country>();
        const auto name = contact_json["person"]["name"].get<udt::name>();

        CHECK(age == a);
        CHECK(name == n);
        CHECK(country == c);
        CHECK(address == addr);
        CHECK(person == sfinae_addict);
        CHECK(contact == cpp_programmer);
        CHECK(contacts == book.m_contacts);
        CHECK(book_name == udt::name{"C++"});
        CHECK(book == parsed_book);
    }
}

namespace udt
{
struct legacy_type
{
    std::string number;
};
}

namespace nlohmann
{
template <typename T>
struct adl_serializer<std::shared_ptr<T>>
{
    static void to_json(json& j, std::shared_ptr<T> const& opt)
    {
        if (opt)
        {
            j = *opt;
        }
        else
        {
            j = nullptr;
        }
    }

    static void from_json(json const& j, std::shared_ptr<T>& opt)
    {
        if (j.is_null())
        {
            opt = nullptr;
        }
        else
        {
            opt.reset(new T(j.get<T>()));
        }
    }
};

template <>
struct adl_serializer<udt::legacy_type>
{
    static void to_json(json& j, udt::legacy_type const& l)
    {
        j = std::stoi(l.number);
    }

    static void from_json(json const& j, udt::legacy_type& l)
    {
        l.number = std::to_string(j.get<int>());
    }
};
}

TEST_CASE("adl_serializer specialization", "[udt]")
{
    SECTION("partial specialization")
    {
        SECTION("to_json")
        {
            std::shared_ptr<udt::person> optPerson;

            json j = optPerson;
            CHECK(j.is_null());

            optPerson.reset(new udt::person{{42}, {"John Doe"}});
            j = optPerson;
            CHECK_FALSE(j.is_null());

            CHECK(j.get<udt::person>() == *optPerson);
        }

        SECTION("from_json")
        {
            auto person = udt::person{{42}, {"John Doe"}};
            json j = person;

            auto optPerson = j.get<std::shared_ptr<udt::person>>();
            REQUIRE(optPerson);
            CHECK(*optPerson == person);

            j = nullptr;
            optPerson = j.get<std::shared_ptr<udt::person>>();
            CHECK(!optPerson);
        }
    }

    SECTION("total specialization")
    {
        SECTION("to_json")
        {
            udt::legacy_type lt{"4242"};

            json j = lt;
            CHECK(j.get<int>() == 4242);
        }

        SECTION("from_json")
        {
            json j = 4242;
            auto lt = j.get<udt::legacy_type>();
            CHECK(lt.number == "4242");
        }
    }
}

namespace nlohmann
{
// this might work in the future, not in the scope of this PR though
// we have to make this very clear in the doc
template <typename T>
struct adl_serializer<std::vector<T>>
{
    static void to_json(json& j, std::vector<T> const& opt)
    {
    }

    static void from_json(json const& j, std::vector<T>& opt)
    {
    }
};
}

TEST_CASE("current supported types are preferred over specializations", "[udt]")
{

    json j = std::vector<int> {1, 2, 3};
    auto f = j.get<std::vector<int>>();
    CHECK((f == std::vector<int> {1, 2, 3}));
}

namespace nlohmann
{
template <typename T>
struct adl_serializer<std::unique_ptr<T>>
{
    static void to_json(json& j, std::unique_ptr<T> const& opt)
    {
        if (opt)
        {
            j = *opt;
        }
        else
        {
            j = nullptr;
        }
    }

    // this is the overload needed for non-copyable types,
    // should we add a priority tag in the implementation to prefer this overload if it exists?
    static std::unique_ptr<T> from_json(json const& j)
    {
        if (j.is_null())
        {
            return nullptr;
        }
        else
        {
            return std::unique_ptr<T>(new T(j.get<T>()));
        }
    }
};
}

TEST_CASE("Non-copyable types", "[udt]")
{
    SECTION("to_json")
    {
        std::unique_ptr<udt::person> optPerson;

        json j = optPerson;
        CHECK(j.is_null());

        optPerson.reset(new udt::person{{42}, {"John Doe"}});
        j = optPerson;
        CHECK_FALSE(j.is_null());

        CHECK(j.get<udt::person>() == *optPerson);
    }

    SECTION("from_json")
    {
        auto person = udt::person{{42}, {"John Doe"}};
        json j = person;

        auto optPerson = j.get<std::unique_ptr<udt::person>>();
        REQUIRE(optPerson);
        CHECK(*optPerson == person);

        j = nullptr;
        optPerson = j.get<std::unique_ptr<udt::person>>();
        CHECK(!optPerson);
    }
}

// custom serializer
// advanced usage (I did not have a real use case in mind)
template <typename T, typename = typename std::enable_if<std::is_pod<T>::value>::type>
struct pod_serializer
{
    // I could forward-declare this struct, and add a basic_json alias
    template <typename Json>
    static void from_json(Json const& j , T& t)
    {
        auto value = j.template get<std::uint64_t>();
        auto bytes = static_cast<char*>(static_cast<void*>(&value));
        std::memcpy(&t, bytes, sizeof(value));
    }

    template <typename Json>
    static void to_json(Json& j, T const& t)
    {
        auto bytes = static_cast<char const*>(static_cast<void const*>(&t));
        std::uint64_t value = bytes[0];
        for (auto i = 1; i < 8; ++i)
        {
            value |= bytes[i] << 8 * i;
        }

        j = value;
    }
};

namespace udt
{
struct small_pod
{
    int begin;
    char middle;
    short end;
};

bool operator==(small_pod lhs, small_pod rhs)
{
    return std::tie(lhs.begin, lhs.middle, lhs.end) ==
           std::tie(lhs.begin, lhs.middle, lhs.end);
}
}

TEST_CASE("custom serializer for pods", "[udt]")
{
    using custom_json = nlohmann::basic_json<std::map, std::vector, std::string, bool, std::int64_t, std::uint64_t, double, std::allocator, pod_serializer>;

    auto p = udt::small_pod{42, '/', 42};
    custom_json j = p;

    auto p2 = j.get<udt::small_pod>();

    CHECK(p == p2);
}

template <typename T, typename>
struct another_adl_serializer;

using custom_json = nlohmann::basic_json<std::map, std::vector, std::string, bool, std::int64_t, std::uint64_t, double, std::allocator, another_adl_serializer>;

template <typename T, typename>
struct another_adl_serializer
{
    static void from_json(custom_json const& j , T& t)
    {
        using nlohmann::from_json;
        from_json(j, t);
    }

    static void to_json(custom_json& j , T const& t)
    {
        using nlohmann::to_json;
        to_json(j, t);
    }
};

TEST_CASE("custom serializer that does adl by default", "[udt]")
{
    using json = nlohmann::json;

    auto me = udt::person{23, "theo", udt::country::france};

    json j = me;
    custom_json cj = me;

    CHECK(j.dump() == cj.dump());

    CHECK(me == j.get<udt::person>());
    CHECK(me == cj.get<udt::person>());
}
