//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>

#include "custom_key_test.hpp"

// object type whose key type has no conversion, but size() and c_str() (see custom_key_test.hpp)
using custom_key_test::json_c_str;

TEST_CASE("custom object key types: copy (json_c_str)")
{
    custom_key_test::test_copy<json_c_str>();
}

TEST_CASE("custom object key types: parse (json_c_str)")
{
    custom_key_test::test_parse<json_c_str>();
}

TEST_CASE("custom object key types: merge_patch, update, and insert (json_c_str)")
{
    custom_key_test::test_patch<json_c_str>();
}

TEST_CASE("custom object key types: at() reports a missing key (json_c_str)")
{
    custom_key_test::test_at<json_c_str>();
}

TEST_CASE("custom object key types: CBOR (json_c_str)")
{
    custom_key_test::test_cbor<json_c_str>();
}

TEST_CASE("custom object key types: MessagePack (json_c_str)")
{
    custom_key_test::test_msgpack<json_c_str>();
}
