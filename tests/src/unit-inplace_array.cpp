//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.11.2
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2022 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <array>
#include <string>
#include <iostream>

#include <nlohmann/json.hpp>

using json = nlohmann::json;
using ordered_json = nlohmann::ordered_json;


class Person
{
  public:
    //Person(){ std::cout<<"Person constructor\n";}
    int age;
    std::string name;
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(Person, name, age);

    int count{1};   // the data must not be reset
};

class SchoolA
{
  public:
    //SchoolA(){ std::cout<<"School constructor\n";}
    std::array<Person, 2> persons;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(SchoolA, persons);
};
class SchoolB
{
  public:
    //SchoolB(){ std::cout<<"School constructor\n";}

    Person persons[2];

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(SchoolB, persons);
};


TEST_CASE("inplace_array<nlohmann::json>")
{

    json obj = R"({"persons":[{"age":100, "name":"alex"}, {"age":200, "name":"edmond"}]})"_json;

    {
        SchoolA   s;
        from_json(obj, s);
        CHECK(s.persons[0].age == 100);

        s.persons[0].count = 88;

        from_json(obj, s);
        CHECK(s.persons[0].count == 88);
    }

    {
        SchoolB   s;
        from_json(obj, s);

        CHECK(s.persons[0].age == 100);

        s.persons[0].count = 88;

        from_json(obj, s);
        CHECK(s.persons[0].count == 88);
    }

}
