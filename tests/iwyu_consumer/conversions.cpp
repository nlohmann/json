//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// See values.cpp: the conversion macros and nlohmann::adl_serializer must be available through
// <nlohmann/json.hpp> alone. NLOHMANN_JSON_SERIALIZE_ENUM (from the same header as
// NLOHMANN_DEFINE_TYPE_INTRUSIVE) is left out: IWYU attributes the basic_json comparison in its
// expansion to an unrelated standard header, the ambiguity described for json.hpp in cmake/ci.cmake.

#include <string>

#include <nlohmann/json.hpp>

namespace ns
{
struct person
{
    std::string name;
    int age;
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(person, name, age)
};

struct legacy
{
    int value;
};
} // namespace ns

namespace nlohmann
{
template<>
struct adl_serializer<ns::legacy>
{
    static void to_json(json& j, const ns::legacy& l)
    {
        j = l.value;
    }

    static void from_json(const json& j, ns::legacy& l)
    {
        l.value = j.get<int>();
    }
};
} // namespace nlohmann

int main()
{
    ns::person ada;
    ada.name = "Ada";
    ada.age = 36;
    ns::legacy one;
    one.value = 1;

    const nlohmann::json j = ada;
    const auto p = j.get<ns::person>();
    const auto l = nlohmann::json(one).get<ns::legacy>();
    return p.age - 36 + l.value - 1;
}
