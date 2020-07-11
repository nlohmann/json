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
