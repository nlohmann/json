//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using json = nlohmann::json;
using ordered_json = nlohmann::ordered_json;

namespace
{
// call format_as() the same way fmt's ADL-based dispatch would: unqualified,
// found only via argument-dependent lookup on the (namespace-qualified) argument type.
template<typename BasicJsonType>
std::string call_format_as_via_adl(const BasicJsonType& j)
{
    return format_as(j);
}
} // namespace

TEST_CASE("format_as<nlohmann::json>")
{
    // null
    CHECK(format_as(json(nullptr)) == json(nullptr).dump());

    // boolean
    CHECK(format_as(json(true)) == json(true).dump());
    CHECK(format_as(json(false)) == json(false).dump());

    // string (including a value that needs escaping/UTF-8 handling)
    CHECK(format_as(json("")) == json("").dump());
    CHECK(format_as(json("foo")) == json("foo").dump());
    CHECK(format_as(json("foo\"bar\\baz\nqux")) == json("foo\"bar\\baz\nqux").dump());
    CHECK(format_as(json("\xc3\xa4\xc3\xb6\xc3\xbc")) == json("\xc3\xa4\xc3\xb6\xc3\xbc").dump());

    // number
    CHECK(format_as(json(0)) == json(0).dump());
    CHECK(format_as(json(-1)) == json(-1).dump());
    CHECK(format_as(json(static_cast<unsigned>(42))) == json(static_cast<unsigned>(42)).dump());
    CHECK(format_as(json(42.23)) == json(42.23).dump());

    // array
    CHECK(format_as(json::array()) == json::array().dump());
    CHECK(format_as(json::array({1, 2, 3})) == json::array({1, 2, 3}).dump());

    // object
    CHECK(format_as(json::object()) == json::object().dump());
    CHECK(format_as(json::object({{"foo", "bar"}})) == json::object({{"foo", "bar"}}).dump());

    // nested/mixed structure
    const json j_nested = {{"foo", 1}, {"bar", {1, 2, 3}}, {"baz", {{"a", nullptr}, {"b", false}}}};
    CHECK(format_as(j_nested) == j_nested.dump());

    // binary
    CHECK(format_as(json::binary({})) == json::binary({}).dump());
    CHECK(format_as(json::binary({1, 2, 3}, 42)) == json::binary({1, 2, 3}, 42).dump());

    // discarded
    CHECK(format_as(json(json::value_t::discarded)) == json(json::value_t::discarded).dump());
}

TEST_CASE("format_as<nlohmann::ordered_json>")
{
    // spot-check a non-default basic_json instantiation, since
    // NLOHMANN_BASIC_JSON_TPL_DECLARATION must deduce correctly there too
    CHECK(format_as(ordered_json(nullptr)) == ordered_json(nullptr).dump());
    CHECK(format_as(ordered_json::object({{"foo", "bar"}, {"baz", 42}})) ==
    ordered_json::object({{"foo", "bar"}, {"baz", 42}}).dump());
    CHECK(format_as(ordered_json::array({1, 2, 3})) == ordered_json::array({1, 2, 3}).dump());
}

TEST_CASE("format_as<nlohmann::json> is found via ADL")
{
    // this is how fmt actually calls it: unqualified, relying on argument-dependent
    // lookup finding nlohmann::format_as via the argument's namespace
    const json j = {{"foo", 1}, {"bar", {1, 2, 3}}};
    CHECK(call_format_as_via_adl(j) == j.dump());

    const ordered_json oj = {{"foo", 1}, {"bar", {1, 2, 3}}};
    CHECK(call_format_as_via_adl(oj) == oj.dump());
}
