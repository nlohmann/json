//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.11.2
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2022 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
#include <exception>

struct Foo
{
    int a;
    int b;
};

namespace nlohmann
{
template <>
struct adl_serializer<Foo>
{
    static void to_json(json& j, Foo const& f)
    {
        switch (f.b)
        {
            case 0:
                j["a"] = f.a;
                break;
            case 1:
                j[0] = f.a;
                break;
            default:
                j = "test";
        }
        if (f.a == 1)
        {
            throw std::runtime_error("b is invalid");
        }
    }
};
}

TEST_CASE("check_for_mem_leak_on_adl_to_json-1")
{
    try
    {
        nlohmann::json j = Foo {1, 0};
    }
    catch (...)
    {
        // just ignore the exception in this POC
    }
}

TEST_CASE("check_for_mem_leak_on_adl_to_json-2")
{
    try
    {
        nlohmann::json j = Foo {1, 1};
    }
    catch (...)
    {
        // just ignore the exception in this POC
    }
}

TEST_CASE("check_for_mem_leak_on_adl_to_json-2")
{
    try
    {
        nlohmann::json j = Foo {1, 2};
    }
    catch (...)
    {
        // just ignore the exception in this POC
    }
}


