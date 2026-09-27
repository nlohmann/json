//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// cmake/test.cmake selects the C++ standard versions with which to build a
// unit test based on the presence of JSON_HAS_CPP_<VERSION> macros.
// The regression below only showed on C++17, so build this file for every
// standard like the other regression tests:
// JSON_HAS_CPP_17 JSON_HAS_CPP_20 (do not remove; see note at top of file)

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using json = nlohmann::json;

/////////////////////////////////////////////////////////////////////
// for #4825 - explicitly instantiating basic_json must compile; this
// forces instantiation of binary_writer::write_bjdata_ndarray, whose
// static_cast<string_t> was ambiguous under explicit instantiation on
// C++17. Merely compiling this translation unit is the regression test.
//
// The instantiation compiles every member function, so it has a file of its
// own: in unit-regression3.cpp it made the object too large for the MinGW
// linker to relocate (see #5511).
/////////////////////////////////////////////////////////////////////
template class nlohmann::basic_json<>;

TEST_CASE("explicit instantiation of basic_json (#4825)")
{
    const json j = {1, "two", 3.0};
    CHECK(j.size() == 3);
    CHECK(json::from_bjdata(json::to_bjdata(j)) == j);
}
