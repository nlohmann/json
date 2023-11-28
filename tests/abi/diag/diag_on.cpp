//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.11.3
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2023 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#undef JSON_DIAGNOSTICS
#define JSON_DIAGNOSTICS 1
#include <nlohmann/json.hpp>

#include "diag.hpp"

std::size_t json_sizeof_diag_on()
{
    return sizeof(nlohmann::json);
}

std::size_t json_sizeof_diag_on_explicit()
{
    return sizeof(::NLOHMANN_JSON_NAMESPACE::json);
}

void json_at_diag_on()
{
    using nlohmann::json;
    json j = json{{"foo", json::object()}};
    j.at(json::json_pointer("/foo/bar"));
}
