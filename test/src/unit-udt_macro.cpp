/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.8.0
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

#include <string>
#include <vector>
#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

namespace persons
{
class person_with_private_data
{
  private:
    std::string name = "";
    int age = 0;
    json metadata = nullptr;

  public:
    bool operator==(const person_with_private_data& rhs) const
    {
        return name == rhs.name && age == rhs.age && metadata == rhs.metadata;
    }

    person_with_private_data() = default;
    person_with_private_data(std::string name_, int age_, json metadata_)
        : name(std::move(name_))
        , age(age_)
        , metadata(std::move(metadata_))
    {}

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(person_with_private_data, age, name, metadata)
};

class person_without_private_data_1
{
  public:
    std::string name = "";
    int age = 0;
    json metadata = nullptr;

    bool operator==(const person_without_private_data_1& rhs) const
    {
        return name == rhs.name && age == rhs.age && metadata == rhs.metadata;
    }

    person_without_private_data_1() = default;
    person_without_private_data_1(std::string name_, int age_, json metadata_)
        : name(std::move(name_))
        , age(age_)
        , metadata(std::move(metadata_))
    {}

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(person_without_private_data_1, age, name, metadata)
};

class person_without_private_data_2
{
  public:
    std::string name = "";
    int age = 0;
    json metadata = nullptr;

    bool operator==(const person_without_private_data_2& rhs) const
    {
        return name == rhs.name && age == rhs.age && metadata == rhs.metadata;
    }

    person_without_private_data_2() = default;
    person_without_private_data_2(std::string name_, int age_, json metadata_)
        : name(std::move(name_))
        , age(age_)
        , metadata(std::move(metadata_))
    {}
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(person_without_private_data_2, age, name, metadata)

class person_with_private_alphabet
{
  public:
    bool operator==(const person_with_private_alphabet& other)
    {
        return std::tie(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z) ==
               std::tie(other.a, other.b, other.c, other.d, other.e, other.f, other.g, other.h, other.i, other.j, other.k, other.l, other.m, other.n, other.o, other.p, other.q, other.r, other.s, other.t, other.u, other.v, other.w, other.x, other.y, other.z);
    }

  private:
    int a;
    int b;
    int c;
    int d;
    int e;
    int f;
    int g;
    int h;
    int i;
    int j;
    int k;
    int l;
    int m;
    int n;
    int o;
    int p;
    int q;
    int r;
    int s;
    int t;
    int u;
    int v;
    int w;
    int x;
    int y;
    int z;
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(person_with_private_alphabet, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z)
};

class person_with_public_alphabet
{
  public:
    bool operator==(const person_with_public_alphabet& other)
    {
        return std::tie(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z) ==
               std::tie(other.a, other.b, other.c, other.d, other.e, other.f, other.g, other.h, other.i, other.j, other.k, other.l, other.m, other.n, other.o, other.p, other.q, other.r, other.s, other.t, other.u, other.v, other.w, other.x, other.y, other.z);
    }

    int a;
    int b;
    int c;
    int d;
    int e;
    int f;
    int g;
    int h;
    int i;
    int j;
    int k;
    int l;
    int m;
    int n;
    int o;
    int p;
    int q;
    int r;
    int s;
    int t;
    int u;
    int v;
    int w;
    int x;
    int y;
    int z;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(person_with_public_alphabet, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z)

} // namespace persons

TEST_CASE_TEMPLATE("Serialization/deserialization via NLOHMANN_DEFINE_TYPE_INTRUSIVE", T,
                   persons::person_with_private_data,
                   persons::person_without_private_data_1,
                   persons::person_without_private_data_2)
{
    SECTION("person")
    {
        // serialization
        T p1("Erik", 1, {{"haircuts", 2}});
        CHECK(json(p1).dump() == "{\"age\":1,\"metadata\":{\"haircuts\":2},\"name\":\"Erik\"}");

        // deserialization
        T p2 = json(p1);
        CHECK(p2 == p1);

        // roundtrip
        CHECK(T(json(p1)) == p1);
        CHECK(json(T(json(p1))) == json(p1));

        // check exception in case of missing field
        json j = json(p1);
        j.erase("age");
        T p3;
        CHECK_THROWS_WITH_AS(p3 = json(j), "[json.exception.out_of_range.403] key 'age' not found", json::out_of_range);
    }
}

TEST_CASE_TEMPLATE("Serialization/deserialization of classes with 26 public/private member variables via NLOHMANN_DEFINE_TYPE_INTRUSIVE and NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE", T,
                   persons::person_with_private_alphabet,
                   persons::person_with_public_alphabet)
{
    SECTION("alphabet")
    {
        {
            T obj1;
            nlohmann::json j = obj1; //via json object
            T obj2;
            j.get_to(obj2);
            CHECK(obj1 == obj2);
        }

        {
            T obj1;
            nlohmann::json j1 = obj1; //via json string
            std::string s = j1.dump();
            nlohmann::json j2 = nlohmann::json::parse(s);
            T obj2;
            j2.get_to(obj2);
            CHECK(obj1 == obj2);
        }

        {
            T obj1;
            nlohmann::json j1 = obj1; //via msgpack
            std::vector<uint8_t> buf = nlohmann::json::to_msgpack(j1);
            nlohmann::json j2 = nlohmann::json::from_msgpack(buf);
            T obj2;
            j2.get_to(obj2);
            CHECK(obj1 == obj2);
        }

        {
            T obj1;
            nlohmann::json j1 = obj1; //via bson
            std::vector<uint8_t> buf = nlohmann::json::to_bson(j1);
            nlohmann::json j2 = nlohmann::json::from_bson(buf);
            T obj2;
            j2.get_to(obj2);
            CHECK(obj1 == obj2);
        }

        {
            T obj1;
            nlohmann::json j1 = obj1; //via cbor
            std::vector<uint8_t> buf = nlohmann::json::to_cbor(j1);
            nlohmann::json j2 = nlohmann::json::from_cbor(buf);
            T obj2;
            j2.get_to(obj2);
            CHECK(obj1 == obj2);
        }

        {
            T obj1;
            nlohmann::json j1 = obj1; //via ubjson
            std::vector<uint8_t> buf = nlohmann::json::to_ubjson(j1);
            nlohmann::json j2 = nlohmann::json::from_ubjson(buf);
            T obj2;
            j2.get_to(obj2);
            CHECK(obj1 == obj2);
        }
    }
}
