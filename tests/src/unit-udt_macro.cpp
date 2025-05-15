//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013 - 2025 Niels Lohmann <https://nlohmann.me>
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
    std::string name{}; // NOLINT(readability-redundant-member-init)
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

class derived_person_with_private_data : public person_with_private_data
{
  private:
    std::string hair_color{"blue"};

  public:
    bool operator==(const derived_person_with_private_data& rhs) const
    {
        return person_with_private_data::operator==(rhs) && hair_color == rhs.hair_color;
    }

    derived_person_with_private_data() = default;
    derived_person_with_private_data(std::string name_, int age_, json metadata_, std::string hair_color_)
        : person_with_private_data(std::move(name_), age_, std::move(metadata_))
        , hair_color(std::move(hair_color_))
    {}

    NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE(derived_person_with_private_data, person_with_private_data, hair_color)
};

class person_with_private_data_2
{
  private:
    std::string name{}; // NOLINT(readability-redundant-member-init)
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

class derived_person_with_private_data_2 : public person_with_private_data_2
{
  private:
    std::string hair_color{"blue"};

  public:
    bool operator==(const derived_person_with_private_data_2& rhs) const
    {
        return person_with_private_data_2::operator==(rhs) && hair_color == rhs.hair_color;
    }

    derived_person_with_private_data_2() = default;
    derived_person_with_private_data_2(std::string name_, int age_, json metadata_, std::string hair_color_)
        : person_with_private_data_2(std::move(name_), age_, std::move(metadata_))
        , hair_color(std::move(hair_color_))
    {}

    std::string getHairColor() const
    {
        return hair_color;
    }

    NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_DEFAULT(derived_person_with_private_data_2, person_with_private_data_2, hair_color)
};

class person_without_private_data_1
{
  public:
    std::string name{}; // NOLINT(readability-redundant-member-init)
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

class derived_person_without_private_data_1 : public person_without_private_data_1
{
  public:
    std::string hair_color{"blue"};

  public:
    bool operator==(const derived_person_without_private_data_1& rhs) const
    {
        return person_without_private_data_1::operator==(rhs) && hair_color == rhs.hair_color;
    }

    derived_person_without_private_data_1() = default;
    derived_person_without_private_data_1(std::string name_, int age_, json metadata_, std::string hair_color_)
        : person_without_private_data_1(std::move(name_), age_, std::move(metadata_))
        , hair_color(std::move(hair_color_))
    {}

    NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE(derived_person_without_private_data_1, person_without_private_data_1, hair_color)
};

class person_without_private_data_2
{
  public:
    std::string name{}; // NOLINT(readability-redundant-member-init)
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

// NOLINTNEXTLINE(misc-use-internal-linkage)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(person_without_private_data_2, age, name, metadata)

class derived_person_without_private_data_2 : public person_without_private_data_2
{
  public:
    std::string hair_color{"blue"};

  public:
    bool operator==(const derived_person_without_private_data_2& rhs) const
    {
        return person_without_private_data_2::operator==(rhs) && hair_color == rhs.hair_color;
    }

    derived_person_without_private_data_2() = default;
    derived_person_without_private_data_2(std::string name_, int age_, json metadata_, std::string hair_color_)
        : person_without_private_data_2(std::move(name_), age_, std::move(metadata_))
        , hair_color(std::move(hair_color_))
    {}
};

// NOLINTNEXTLINE(misc-use-internal-linkage)
NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE(derived_person_without_private_data_2, person_without_private_data_2, hair_color)

class person_without_private_data_3
{
  public:
    std::string name{}; // NOLINT(readability-redundant-member-init)
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

// NOLINTNEXTLINE(misc-use-internal-linkage)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(person_without_private_data_3, age, name, metadata)

class derived_person_without_private_data_3 : public person_without_private_data_3
{
  public:
    std::string hair_color{"blue"};

  public:
    bool operator==(const derived_person_without_private_data_3& rhs) const
    {
        return person_without_private_data_3::operator==(rhs) && hair_color == rhs.hair_color;
    }

    derived_person_without_private_data_3() = default;
    derived_person_without_private_data_3(std::string name_, int age_, json metadata_, std::string hair_color_)
        : person_without_private_data_3(std::move(name_), age_, std::move(metadata_))
        , hair_color(std::move(hair_color_))
    {}

    std::string getHairColor() const
    {
        return hair_color;
    }
};

// NOLINTNEXTLINE(misc-use-internal-linkage)
NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_DEFAULT(derived_person_without_private_data_3, person_without_private_data_3, hair_color)

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

// NOLINTNEXTLINE(misc-use-internal-linkage)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(person_with_public_alphabet, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z)

class person_without_default_constructor_1
{
  public:
    std::string name;
    int age;

    bool operator==(const person_without_default_constructor_1& other) const
    {
        return name == other.name && age == other.age;
    }

    person_without_default_constructor_1(std::string name_, int age_)
        : name{std::move(name_)}
        , age{age_}
    {}

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_ONLY_SERIALIZE(person_without_default_constructor_1, name, age)
};

class person_without_default_constructor_2
{
  public:
    std::string name;
    int age;

    bool operator==(const person_without_default_constructor_2& other) const
    {
        return name == other.name && age == other.age;
    }

    person_without_default_constructor_2(std::string name_, int age_)
        : name{std::move(name_)}
        , age{age_}
    {}
};

// NOLINTNEXTLINE(misc-use-internal-linkage)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(person_without_default_constructor_2, name, age)

class derived_person_only_serialize_public : public person_without_default_constructor_1
{
  public:
    std::string hair_color;

    derived_person_only_serialize_public(std::string name_, int age_, std::string hair_color_)
        : person_without_default_constructor_1(std::move(name_), age_)
        , hair_color(std::move(hair_color_))
    {}
};

// NOLINTNEXTLINE(misc-use-internal-linkage)
NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(derived_person_only_serialize_public, person_without_default_constructor_1, hair_color)

class derived_person_only_serialize_private : person_without_default_constructor_1
{
  private:
    std::string hair_color;
  public:
    derived_person_only_serialize_private(std::string name_, int age_, std::string hair_color_)
        : person_without_default_constructor_1(std::move(name_), age_)
        , hair_color(std::move(hair_color_))
    {}

    NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_ONLY_SERIALIZE(derived_person_only_serialize_private, person_without_default_constructor_1, hair_color)
};

} // namespace persons

TEST_CASE_TEMPLATE("Serialization/deserialization via NLOHMANN_DEFINE_TYPE_INTRUSIVE and NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE", Pair, // NOLINT(readability-math-missing-parentheses)
                   std::pair<nlohmann::json, persons::person_with_private_data>,
                   std::pair<nlohmann::json, persons::person_without_private_data_1>,
                   std::pair<nlohmann::json, persons::person_without_private_data_2>,
                   std::pair<nlohmann::ordered_json, persons::person_with_private_data>,
                   std::pair<nlohmann::ordered_json, persons::person_without_private_data_1>,
                   std::pair<nlohmann::ordered_json, persons::person_without_private_data_2>)
{
    using Json = typename Pair::first_type;
    using T = typename Pair::second_type;
    constexpr bool is_ordered = std::is_same<Json, nlohmann::ordered_json>::value;

    SECTION("person")
    {
        // serialization
        T p1("Erik", 1, {{"haircuts", 2}});
        CHECK(Json(p1).dump() == (is_ordered ?
                                  R"({"age":1,"name":"Erik","metadata":{"haircuts":2}})" :
                                  R"({"age":1,"metadata":{"haircuts":2},"name":"Erik"})"));

        // deserialization
        auto p2 = Json(p1).template get<T>();
        CHECK(p2 == p1);

        // roundtrip
        CHECK(T(Json(p1)) == p1);
        CHECK(Json(T(Json(p1))) == Json(p1));

        // check exception in case of missing field
        Json j = Json(p1);
        j.erase("age");
        CHECK_THROWS_WITH_AS(j.template get<T>(), "[json.exception.out_of_range.403] key 'age' not found", typename Json::out_of_range);
    }
}

TEST_CASE_TEMPLATE("Serialization/deserialization via NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE and NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE", Pair, // NOLINT(readability-math-missing-parentheses)
                   std::pair<nlohmann::json, persons::derived_person_with_private_data>,
                   std::pair<nlohmann::json, persons::derived_person_without_private_data_1>,
                   std::pair<nlohmann::json, persons::derived_person_without_private_data_2>,
                   std::pair<nlohmann::ordered_json, persons::derived_person_with_private_data>,
                   std::pair<nlohmann::ordered_json, persons::derived_person_without_private_data_1>,
                   std::pair<nlohmann::ordered_json, persons::derived_person_without_private_data_2>)
{
    using Json = typename Pair::first_type;
    using T = typename Pair::second_type;
    constexpr bool is_ordered = std::is_same<Json, nlohmann::ordered_json>::value;

    SECTION("person")
    {
        // serialization
        T p1("Erik", 1, {{"haircuts", 2}}, "red");
        CHECK(Json(p1).dump() == (is_ordered ?
                                  R"({"age":1,"name":"Erik","metadata":{"haircuts":2},"hair_color":"red"})" :
                                  R"({"age":1,"hair_color":"red","metadata":{"haircuts":2},"name":"Erik"})"));

        // deserialization
        auto p2 = Json(p1).template get<T>();
        CHECK(p2 == p1);

        // roundtrip
        CHECK(T(Json(p1)) == p1);
        CHECK(Json(T(Json(p1))) == Json(p1));

        // check exception in case of missing field
        Json j = Json(p1);
        j.erase("age");
        CHECK_THROWS_WITH_AS(j.template get<T>(), "[json.exception.out_of_range.403] key 'age' not found", typename Json::out_of_range);
    }
}

TEST_CASE_TEMPLATE("Serialization/deserialization via NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT and NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT", Pair, // NOLINT(readability-math-missing-parentheses)
                   std::pair<nlohmann::json, persons::person_with_private_data_2>,
                   std::pair<nlohmann::json, persons::person_without_private_data_3>,
                   std::pair<nlohmann::ordered_json, persons::person_with_private_data_2>,
                   std::pair<nlohmann::ordered_json, persons::person_without_private_data_3>)
{
    using Json = typename Pair::first_type;
    using T = typename Pair::second_type;
    constexpr bool is_ordered = std::is_same<Json, nlohmann::ordered_json>::value;

    SECTION("person with default values")
    {
        // serialization of default constructed object
        const T p0{};
        CHECK(Json(p0).dump() == (is_ordered ?
                                  R"({"age":0,"name":"","metadata":null})" :
                                  R"({"age":0,"metadata":null,"name":""})"));

        // serialization
        T p1("Erik", 1, {{"haircuts", 2}});
        CHECK(Json(p1).dump() == (is_ordered ?
                                  R"({"age":1,"name":"Erik","metadata":{"haircuts":2}})" :
                                  R"({"age":1,"metadata":{"haircuts":2},"name":"Erik"})"));

        // deserialization
        auto p2 = Json(p1).template get<T>();
        CHECK(p2 == p1);

        // roundtrip
        CHECK(T(Json(p1)) == p1);
        CHECK(Json(T(Json(p1))) == Json(p1));

        // check default value in case of missing field
        Json j = Json(p1);
        j.erase("name");
        j.erase("age");
        j.erase("metadata");
        const T p3 = j.template get<T>();
        CHECK(p3.getName() == "");
        CHECK(p3.getAge() == 0);
        CHECK(p3.getMetadata() == nullptr);

        // check default value in case of empty json
        const Json j4;
        const T p4 = j4.template get<T>();
        CHECK(p4.getName() == "");
        CHECK(p4.getAge() == 0);
        CHECK(p4.getMetadata() == nullptr);
    }
}

TEST_CASE_TEMPLATE("Serialization/deserialization via NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_DEFAULT and NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_DEFAULT", Pair, // NOLINT(readability-math-missing-parentheses)
                   std::pair<nlohmann::json, persons::derived_person_with_private_data_2>,
                   std::pair<nlohmann::json, persons::derived_person_without_private_data_3>,
                   std::pair<nlohmann::ordered_json, persons::derived_person_with_private_data_2>,
                   std::pair<nlohmann::ordered_json, persons::derived_person_without_private_data_3>)
{
    using Json = typename Pair::first_type;
    using T = typename Pair::second_type;
    constexpr bool is_ordered = std::is_same<Json, nlohmann::ordered_json>::value;

    SECTION("derived person with default values")
    {
        // serialization of default constructed object
        const T p0{};
        CHECK(Json(p0).dump() == (is_ordered ?
                                  R"({"age":0,"name":"","metadata":null,"hair_color":"blue"})" :
                                  R"({"age":0,"hair_color":"blue","metadata":null,"name":""})"));

        // serialization
        T p1("Erik", 1, {{"haircuts", 2}}, "red");
        CHECK(Json(p1).dump() == (is_ordered ?
                                  R"({"age":1,"name":"Erik","metadata":{"haircuts":2},"hair_color":"red"})" :
                                  R"({"age":1,"hair_color":"red","metadata":{"haircuts":2},"name":"Erik"})"));

        // deserialization
        auto p2 = Json(p1).template get<T>();
        CHECK(p2 == p1);

        // roundtrip
        CHECK(T(Json(p1)) == p1);
        CHECK(Json(T(Json(p1))) == Json(p1));

        // check default value in case of missing field
        Json j = Json(p1);
        j.erase("name");
        j.erase("age");
        j.erase("metadata");
        j.erase("hair_color");
        const T p3 = j.template get<T>();
        CHECK(p3.getName() == "");
        CHECK(p3.getAge() == 0);
        CHECK(p3.getMetadata() == nullptr);
        CHECK(p3.getHairColor() == "blue");
    }
}

TEST_CASE_TEMPLATE("Serialization/deserialization of classes with 26 public/private member variables via NLOHMANN_DEFINE_TYPE_INTRUSIVE and NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE", Pair, // NOLINT(readability-math-missing-parentheses)
                   std::pair<nlohmann::json, persons::person_with_private_alphabet>,
                   std::pair<nlohmann::json, persons::person_with_public_alphabet>,
                   std::pair<nlohmann::ordered_json, persons::person_with_private_alphabet>,
                   std::pair<nlohmann::ordered_json, persons::person_with_public_alphabet>)
{
    using Json = typename Pair::first_type;
    using T = typename Pair::second_type;

    SECTION("alphabet")
    {
        T obj1; // NOLINT(misc-const-correctness)
        Json const j = obj1;
        T obj2;
        j.get_to(obj2);
        CHECK(obj1 == obj2);
    }
}

TEST_CASE_TEMPLATE("Serialization of non-default-constructible classes via NLOHMANN_DEFINE_TYPE_INTRUSIVE_ONLY_SERIALIZE and NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE", Pair, // NOLINT(readability-math-missing-parentheses)
                   std::pair<nlohmann::json, persons::person_without_default_constructor_1>,
                   std::pair<nlohmann::json, persons::person_without_default_constructor_2>,
                   std::pair<nlohmann::ordered_json, persons::person_without_default_constructor_1>,
                   std::pair<nlohmann::ordered_json, persons::person_without_default_constructor_2>)
{
    using Json = typename Pair::first_type;
    using T = typename Pair::second_type;
    constexpr bool is_ordered = std::is_same<Json, nlohmann::ordered_json>::value;

    SECTION("person")
    {
        // serialization of a single object
        const T person{"Erik", 1};
        CHECK(Json(person).dump() == (is_ordered ?
                                      R"({"name":"Erik","age":1})" :
                                      R"({"age":1,"name":"Erik"})"));

        // serialization of a container with objects
        std::vector<T> const two_persons
        {
            {"Erik", 1},
            {"Kyle", 2}
        };
        CHECK(Json(two_persons).dump() == (is_ordered ?
                                           R"([{"name":"Erik","age":1},{"name":"Kyle","age":2}])" :
                                           R"([{"age":1,"name":"Erik"},{"age":2,"name":"Kyle"}])"));
    }
}

TEST_CASE_TEMPLATE("Serialization of non-default-constructible classes via NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_ONLY_SERIALIZE and NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE", Pair, // NOLINT(readability-math-missing-parentheses)
                   std::pair<nlohmann::json, persons::derived_person_only_serialize_public>,
                   std::pair<nlohmann::json, persons::derived_person_only_serialize_private>,
                   std::pair<nlohmann::ordered_json, persons::derived_person_only_serialize_public>,
                   std::pair<nlohmann::ordered_json, persons::derived_person_only_serialize_private>)
{
    using Json = typename Pair::first_type;
    using T = typename Pair::second_type;
    constexpr bool is_ordered = std::is_same<Json, nlohmann::ordered_json>::value;

    SECTION("derived person only serialize")
    {
        // serialization of a single object
        const T person{"Erik", 1, "brown"};
        CHECK(Json(person).dump() == (is_ordered ?
                                      R"({"name":"Erik","age":1,"hair_color":"brown"})" :
                                      R"({"age":1,"hair_color":"brown","name":"Erik"})"));

        // serialization of a container with objects
        std::vector<T> const two_persons
        {
            {"Erik", 1, "brown"},
            {"Kyle", 2, "black"}
        };
        CHECK(Json(two_persons).dump() == (is_ordered ?
                                           R"([{"name":"Erik","age":1,"hair_color":"brown"},{"name":"Kyle","age":2,"hair_color":"black"}])" :
                                           R"([{"age":1,"hair_color":"brown","name":"Erik"},{"age":2,"hair_color":"black","name":"Kyle"}])"));
    }
}
