//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// See values.cpp: the user-defined literals must be available through <nlohmann/json.hpp> alone.

#include <nlohmann/json.hpp>

using namespace nlohmann::literals; // NOLINT(google-build-using-namespace)

int main()
{
    const auto j = R"({"a": [1, 2]})"_json;
    return j.at("/a/1"_json_pointer).get<int>() - 2;
}
