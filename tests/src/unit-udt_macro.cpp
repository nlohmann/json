/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.10.5
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
SPDX-License-Identifier: MIT
Copyright (c) 2013-2022 Niels Lohmann <http://nlohmann.me>.

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
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
using nlohmann::json;

namespace persons
{
#define PERSON_CLASS_BODY(ClassName, Visibility)                                    \
    /* NOLINTNEXTLINE(bugprone-macro-parentheses) */                                \
    Visibility:                                                                     \
    /* NOLINTNEXTLINE(readability-redundant-string-init): collides with -Weffc++ */ \
    std::string name = "";                                                          \
    int age = 0;                                                                    \
    json metadata = nullptr;                                                        \
    public:                                                                         \
    bool operator==(const ClassName& rhs) const                                     \
    {                                                                               \
        return name == rhs.name && age == rhs.age && metadata == rhs.metadata;      \
    }                                                                               \
    ClassName() = default;                                                          \
    ClassName(std::string name_, int age_, json metadata_)                          \
        : name(std::move(name_))                                                    \
        , age(age_)                                                                 \
        , metadata(std::move(metadata_))                                            \
    {}                                                                              \
    std::string getName() const                                                     \
    {                                                                               \
        return name;                                                                \
    }                                                                               \
    int getAge() const                                                              \
    {                                                                               \
        return age;                                                                 \
    }                                                                               \
    json getMetadata() const                                                        \
    {                                                                               \
        return metadata;                                                            \
    }

#define ALPHABET_CLASS_BODY(ClassName, Visibility)   \
    public:                                          \
    bool operator==(const ClassName& other) const    \
    {                                                \
        return a == other.a &&                       \
               b == other.b &&                       \
               c == other.c &&                       \
               d == other.d &&                       \
               e == other.e &&                       \
               f == other.f &&                       \
               g == other.g &&                       \
               h == other.h &&                       \
               i == other.i &&                       \
               j == other.j &&                       \
               k == other.k &&                       \
               l == other.l &&                       \
               m == other.m &&                       \
               n == other.n &&                       \
               o == other.o &&                       \
               p == other.p &&                       \
               q == other.q &&                       \
               r == other.r &&                       \
               s == other.s &&                       \
               t == other.t &&                       \
               u == other.u &&                       \
               v == other.v &&                       \
               w == other.w &&                       \
               x == other.x &&                       \
               y == other.y &&                       \
               z == other.z;                         \
    }                                                \
    /* NOLINTNEXTLINE(bugprone-macro-parentheses) */ \
    Visibility:                                      \
    int a = 0;                                       \
    int b = 0;                                       \
    int c = 0;                                       \
    int d = 0;                                       \
    int e = 0;                                       \
    int f = 0;                                       \
    int g = 0;                                       \
    int h = 0;                                       \
    int i = 0;                                       \
    int j = 0;                                       \
    int k = 0;                                       \
    int l = 0;                                       \
    int m = 0;                                       \
    int n = 0;                                       \
    int o = 0;                                       \
    int p = 0;                                       \
    int q = 0;                                       \
    int r = 0;                                       \
    int s = 0;                                       \
    int t = 0;                                       \
    int u = 0;                                       \
    int v = 0;                                       \
    int w = 0;                                       \
    int x = 0;                                       \
    int y = 0;                                       \
    int z = 0;

class person_with_private_data
{
    PERSON_CLASS_BODY(person_with_private_data, private)
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(person_with_private_data, age, name, metadata)
};

class person_with_private_data_2
{
    PERSON_CLASS_BODY(person_with_private_data_2, private)
    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(person_with_private_data_2, age, name, metadata)
};

class person_without_private_data_1
{
    PERSON_CLASS_BODY(person_without_private_data_1, public)
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(person_without_private_data_1, age, name, metadata)
};

class person_without_private_data_2
{
    PERSON_CLASS_BODY(person_without_private_data_2, public)
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(person_without_private_data_2, age, name, metadata)

class person_without_private_data_3
{
    PERSON_CLASS_BODY(person_without_private_data_3, public)
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(person_without_private_data_3, age, name, metadata)

class person_t_with_private_data
{
    PERSON_CLASS_BODY(person_t_with_private_data, private)
    NLOHMANN_DEFINE_TYPE_INTRUSIVE_T(person_t_with_private_data, age, name, metadata)
};

class person_t_with_private_data_2
{
    PERSON_CLASS_BODY(person_t_with_private_data_2, private)
    NLOHMANN_DEFINE_TYPE_INTRUSIVE_T_WITH_DEFAULT(person_t_with_private_data_2, age, name, metadata)
};

class person_t_without_private_data_1
{
    PERSON_CLASS_BODY(person_t_without_private_data_1, public)
    NLOHMANN_DEFINE_TYPE_INTRUSIVE_T(person_t_without_private_data_1, age, name, metadata)
};

class person_t_without_private_data_2
{
    PERSON_CLASS_BODY(person_t_without_private_data_2, public)
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_T(person_t_without_private_data_2, age, name, metadata)

class person_t_without_private_data_3
{
    PERSON_CLASS_BODY(person_t_without_private_data_3, public)
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_T_WITH_DEFAULT(person_t_without_private_data_3, age, name, metadata)

class person_with_private_alphabet
{
    ALPHABET_CLASS_BODY(person_with_private_alphabet, private)
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(person_with_private_alphabet, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z)
};

class person_with_public_alphabet
{
    ALPHABET_CLASS_BODY(person_with_public_alphabet, public)
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(person_with_public_alphabet, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z)

class person_t_with_private_alphabet
{
    ALPHABET_CLASS_BODY(person_t_with_private_alphabet, private)
    NLOHMANN_DEFINE_TYPE_INTRUSIVE_T(person_t_with_private_alphabet, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z)
};

class person_t_with_public_alphabet
{
    ALPHABET_CLASS_BODY(person_t_with_public_alphabet, public)
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_T(person_t_with_public_alphabet, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z)
}  // namespace persons

// Trick described in https://github.com/onqtam/doctest/blob/master/doc/markdown/parameterized-tests.md
// in note "if you need parameterization on more than 1 type"
template<typename TestedType_, typename BasicJsonType_ = nlohmann::json>
struct TestTypePair
{
    using TestedType = TestedType_;
    using BasicJsonType = BasicJsonType_;
};

#define PERSON_TYPES_TO_TEST                                                        \
    TestTypePair<persons::person_with_private_data>,                                \
    TestTypePair<persons::person_without_private_data_1>,                           \
    TestTypePair<persons::person_without_private_data_2>,                           \
    TestTypePair<persons::person_t_with_private_data>,                              \
    TestTypePair<persons::person_t_without_private_data_1>,                         \
    TestTypePair<persons::person_t_without_private_data_2>,                         \
    TestTypePair<persons::person_t_with_private_data, nlohmann::ordered_json>,      \
    TestTypePair<persons::person_t_without_private_data_1, nlohmann::ordered_json>, \
    TestTypePair<persons::person_t_without_private_data_2, nlohmann::ordered_json>

TEST_CASE_TEMPLATE("Serialization/deserialization via NLOHMANN_DEFINE_TYPE_INTRUSIVE and NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE", PairT, PERSON_TYPES_TO_TEST)
#undef PERSON_TYPES_TO_TEST
{
    using T = typename PairT::TestedType;
    using json_t = typename PairT::BasicJsonType;

    SECTION("person")
    {
        // serialization
        T p1("Erik", 1, {{"haircuts", 2}});
        std::string json_string;
        if (std::is_same<json_t, nlohmann::ordered_json>::value)
        {
            json_string = R"str({"age":1,"name":"Erik","metadata":{"haircuts":2}})str";
        }
        else
        {
            json_string = R"str({"age":1,"metadata":{"haircuts":2},"name":"Erik"})str";
        }
        CHECK(json_t(p1).dump() == json_string);

        // deserialization
        auto p2 = json_t(p1).template get<T>();
        CHECK(p2 == p1);

        // roundtrip
        CHECK(T(json_t(p1)) == p1);
        CHECK(json_t(T(json_t(p1))) == json_t(p1));

        // check exception in case of missing field
        json_t j = json_t(p1);
        j.erase("age");
        CHECK_THROWS_WITH_AS(j.template get<T>(), "[json.exception.out_of_range.403] key 'age' not found", typename json_t::out_of_range);
    }
}

#define PERSON_TYPES_TO_TEST                                                     \
    TestTypePair<persons::person_with_private_data_2>,                           \
    TestTypePair<persons::person_without_private_data_3>,                        \
    TestTypePair<persons::person_t_with_private_data_2>,                         \
    TestTypePair<persons::person_t_without_private_data_3>,                      \
    TestTypePair<persons::person_t_with_private_data_2, nlohmann::ordered_json>, \
    TestTypePair<persons::person_t_without_private_data_3, nlohmann::ordered_json>

TEST_CASE_TEMPLATE("Serialization/deserialization via NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT and NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT", PairT, PERSON_TYPES_TO_TEST)
#undef PERSON_TYPES_TO_TEST
{
    using T = typename PairT::TestedType;
    using json_t = typename PairT::BasicJsonType;

    SECTION("person with default values")
    {
        // serialization of default constructed object
        T p0;
        std::string json_string;
        if (std::is_same<json_t, nlohmann::ordered_json>::value)
        {
            json_string = R"str({"age":0,"name":"","metadata":null})str";
        }
        else
        {
            json_string = R"str({"age":0,"metadata":null,"name":""})str";
        }
        CHECK(json_t(p0).dump() == json_string);

        // serialization
        T p1("Erik", 1, {{"haircuts", 2}});
        if (std::is_same<json_t, nlohmann::ordered_json>::value)
        {
            json_string = R"str({"age":1,"name":"Erik","metadata":{"haircuts":2}})str";
        }
        else
        {
            json_string = R"str({"age":1,"metadata":{"haircuts":2},"name":"Erik"})str";
        }
        CHECK(json_t(p1).dump() == json_string);

        // deserialization
        auto p2 = json_t(p1).template get<T>();
        CHECK(p2 == p1);

        // roundtrip
        CHECK(T(json_t(p1)) == p1);
        CHECK(json_t(T(json_t(p1))) == json_t(p1));

        // check default value in case of missing field
        json_t j = json_t(p1);
        j.erase("name");
        j.erase("age");
        j.erase("metadata");
        T p3 = j.template get<T>();
        CHECK(p3.getName() == "");
        CHECK(p3.getAge() == 0);
        CHECK(p3.getMetadata() == nullptr);
    }
}

#define ALPHABET_PAIRS                                                             \
    TestTypePair<persons::person_with_private_alphabet>,                           \
    TestTypePair<persons::person_with_public_alphabet>,                            \
    TestTypePair<persons::person_t_with_private_alphabet, nlohmann::json>,         \
    TestTypePair<persons::person_t_with_public_alphabet, nlohmann::json>,          \
    TestTypePair<persons::person_t_with_private_alphabet, nlohmann::ordered_json>, \
    TestTypePair<persons::person_t_with_public_alphabet, nlohmann::ordered_json>

TEST_CASE_TEMPLATE("Serialization/deserialization of classes with 26 public/private member variables via NLOHMANN_DEFINE_TYPE_INTRUSIVE and NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE", PairT, ALPHABET_PAIRS)
#undef ALPHABET_PAIRS
{
    using T = typename PairT::TestedType;
    using json_t = typename PairT::BasicJsonType;

    SECTION("alphabet")
    {
        {
            T obj1;
            json_t j = obj1;  //via json object
            T obj2;
            j.get_to(obj2);
            bool ok = (obj1 == obj2);
            CHECK(ok);
        }

        {
            T obj1;
            json_t j1 = obj1;  //via json string
            std::string s = j1.dump();
            json_t j2 = json_t::parse(s);
            T obj2;
            j2.get_to(obj2);
            bool ok = (obj1 == obj2);
            CHECK(ok);
        }

        {
            T obj1;
            json_t j1 = obj1;  //via msgpack
            std::vector<uint8_t> buf = json_t::to_msgpack(j1);
            json_t j2 = json_t::from_msgpack(buf);
            T obj2;
            j2.get_to(obj2);
            bool ok = (obj1 == obj2);
            CHECK(ok);
        }

        {
            T obj1;
            json_t j1 = obj1;  //via bson
            std::vector<uint8_t> buf = json_t::to_bson(j1);
            json_t j2 = json_t::from_bson(buf);
            T obj2;
            j2.get_to(obj2);
            bool ok = (obj1 == obj2);
            CHECK(ok);
        }

        {
            T obj1;
            json_t j1 = obj1;  //via cbor
            std::vector<uint8_t> buf = json_t::to_cbor(j1);
            json_t j2 = json_t::from_cbor(buf);
            T obj2;
            j2.get_to(obj2);
            bool ok = (obj1 == obj2);
            CHECK(ok);
        }

        {
            T obj1;
            json_t j1 = obj1;  //via ubjson
            std::vector<uint8_t> buf = json_t::to_ubjson(j1);
            json_t j2 = json_t::from_ubjson(buf);
            T obj2;
            j2.get_to(obj2);
            bool ok = (obj1 == obj2);
            CHECK(ok);
        }
    }
}
