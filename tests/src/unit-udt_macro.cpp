//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.11.2
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2022 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

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
    std::string name{};
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

class person_with_private_data_2
{
  private:
    std::string name{};
    int age = 0;
    json metadata = nullptr;

  public:
    bool operator==(const person_with_private_data_2& rhs) const
    {
        return name == rhs.name && age == rhs.age && metadata == rhs.metadata;
    }

    person_with_private_data_2() = default;
    person_with_private_data_2(std::string name_, int age_, json metadata_)
        : name(std::move(name_))
        , age(age_)
        , metadata(std::move(metadata_))
    {}

    std::string getName() const
    {
        return name;
    }
    int getAge() const
    {
        return age;
    }
    json getMetadata() const
    {
        return metadata;
    }

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(person_with_private_data_2, age, name, metadata)
};

class person_without_private_data_1
{
  public:
    std::string name{};
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
    std::string name{};
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

class person_without_private_data_3
{
  public:
    std::string name{};
    int age = 0;
    json metadata = nullptr;

    bool operator==(const person_without_private_data_3& rhs) const
    {
        return name == rhs.name && age == rhs.age && metadata == rhs.metadata;
    }

    person_without_private_data_3() = default;
    person_without_private_data_3(std::string name_, int age_, json metadata_)
        : name(std::move(name_))
        , age(age_)
        , metadata(std::move(metadata_))
    {}

    std::string getName() const
    {
        return name;
    }
    int getAge() const
    {
        return age;
    }
    json getMetadata() const
    {
        return metadata;
    }
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(person_without_private_data_3, age, name, metadata)

class person_with_private_alphabet
{
  public:
    bool operator==(const person_with_private_alphabet& other) const
    {
        return  a == other.a &&
                b == other.b &&
                c == other.c &&
                d == other.d &&
                e == other.e &&
                f == other.f &&
                g == other.g &&
                h == other.h &&
                i == other.i &&
                j == other.j &&
                k == other.k &&
                l == other.l &&
                m == other.m &&
                n == other.n &&
                o == other.o &&
                p == other.p &&
                q == other.q &&
                r == other.r &&
                s == other.s &&
                t == other.t &&
                u == other.u &&
                v == other.v &&
                w == other.w &&
                x == other.x &&
                y == other.y &&
                z == other.z;
    }

  private:
    int a = 0;
    int b = 0;
    int c = 0;
    int d = 0;
    int e = 0;
    int f = 0;
    int g = 0;
    int h = 0;
    int i = 0;
    int j = 0;
    int k = 0;
    int l = 0;
    int m = 0;
    int n = 0;
    int o = 0;
    int p = 0;
    int q = 0;
    int r = 0;
    int s = 0;
    int t = 0;
    int u = 0;
    int v = 0;
    int w = 0;
    int x = 0;
    int y = 0;
    int z = 0;
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(person_with_private_alphabet, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z)
};

class person_with_public_alphabet
{
  public:
    bool operator==(const person_with_public_alphabet& other) const
    {
        return  a == other.a &&
                b == other.b &&
                c == other.c &&
                d == other.d &&
                e == other.e &&
                f == other.f &&
                g == other.g &&
                h == other.h &&
                i == other.i &&
                j == other.j &&
                k == other.k &&
                l == other.l &&
                m == other.m &&
                n == other.n &&
                o == other.o &&
                p == other.p &&
                q == other.q &&
                r == other.r &&
                s == other.s &&
                t == other.t &&
                u == other.u &&
                v == other.v &&
                w == other.w &&
                x == other.x &&
                y == other.y &&
                z == other.z;
    }

    int a = 0;
    int b = 0;
    int c = 0;
    int d = 0;
    int e = 0;
    int f = 0;
    int g = 0;
    int h = 0;
    int i = 0;
    int j = 0;
    int k = 0;
    int l = 0;
    int m = 0;
    int n = 0;
    int o = 0;
    int p = 0;
    int q = 0;
    int r = 0;
    int s = 0;
    int t = 0;
    int u = 0;
    int v = 0;
    int w = 0;
    int x = 0;
    int y = 0;
    int z = 0;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(person_with_public_alphabet, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z)

} // namespace persons

TEST_CASE_TEMPLATE("Serialization/deserialization via NLOHMANN_DEFINE_TYPE_INTRUSIVE and NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE", T,
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
        auto p2 = json(p1).get<T>();
        CHECK(p2 == p1);

        // roundtrip
        CHECK(T(json(p1)) == p1);
        CHECK(json(T(json(p1))) == json(p1));

        // check exception in case of missing field
        json j = json(p1);
        j.erase("age");
        CHECK_THROWS_WITH_AS(j.get<T>(), "[json.exception.out_of_range.403] key 'age' not found", json::out_of_range);
    }
}

TEST_CASE_TEMPLATE("Serialization/deserialization via NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT and NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT", T,
                   persons::person_with_private_data_2,
                   persons::person_without_private_data_3)
{
    SECTION("person with default values")
    {
        // serialization of default constructed object
        T p0;
        CHECK(json(p0).dump() == "{\"age\":0,\"metadata\":null,\"name\":\"\"}");

        // serialization
        T p1("Erik", 1, {{"haircuts", 2}});
        CHECK(json(p1).dump() == "{\"age\":1,\"metadata\":{\"haircuts\":2},\"name\":\"Erik\"}");

        // deserialization
        auto p2 = json(p1).get<T>();
        CHECK(p2 == p1);

        // roundtrip
        CHECK(T(json(p1)) == p1);
        CHECK(json(T(json(p1))) == json(p1));

        // check default value in case of missing field
        json j = json(p1);
        j.erase("name");
        j.erase("age");
        j.erase("metadata");
        T p3 = j.get<T>();
        CHECK(p3.getName() == "");
        CHECK(p3.getAge() == 0);
        CHECK(p3.getMetadata() == nullptr);
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
            nlohmann::json const j = obj1; //via json object
            T obj2;
            j.get_to(obj2);
            bool ok = (obj1 == obj2);
            CHECK(ok);
        }

        {
            T obj1;
            nlohmann::json const j1 = obj1; //via json string
            std::string const s = j1.dump();
            nlohmann::json const j2 = nlohmann::json::parse(s);
            T obj2;
            j2.get_to(obj2);
            bool ok = (obj1 == obj2);
            CHECK(ok);
        }

        {
            T obj1;
            nlohmann::json const j1 = obj1; //via msgpack
            std::vector<uint8_t> const buf = nlohmann::json::to_msgpack(j1);
            nlohmann::json const j2 = nlohmann::json::from_msgpack(buf);
            T obj2;
            j2.get_to(obj2);
            bool ok = (obj1 == obj2);
            CHECK(ok);
        }

        {
            T obj1;
            nlohmann::json const j1 = obj1; //via bson
            std::vector<uint8_t> const buf = nlohmann::json::to_bson(j1);
            nlohmann::json const j2 = nlohmann::json::from_bson(buf);
            T obj2;
            j2.get_to(obj2);
            bool ok = (obj1 == obj2);
            CHECK(ok);
        }

        {
            T obj1;
            nlohmann::json const j1 = obj1; //via cbor
            std::vector<uint8_t> const buf = nlohmann::json::to_cbor(j1);
            nlohmann::json const j2 = nlohmann::json::from_cbor(buf);
            T obj2;
            j2.get_to(obj2);
            bool ok = (obj1 == obj2);
            CHECK(ok);
        }

        {
            T obj1;
            nlohmann::json const j1 = obj1; //via ubjson
            std::vector<uint8_t> const buf = nlohmann::json::to_ubjson(j1);
            nlohmann::json const j2 = nlohmann::json::from_ubjson(buf);
            T obj2;
            j2.get_to(obj2);
            bool ok = (obj1 == obj2);
            CHECK(ok);
        }
    }
}
