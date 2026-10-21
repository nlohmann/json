//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// Uses the library the way a client does, including only <nlohmann/json.hpp>. ci_single_binaries
// runs include-what-you-use and clang-tidy's misc-include-cleaner on this file and fails if either
// asks for another nlohmann header, which would mean json.hpp does not export it (issue #5812).

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

int main()
{
    // brace initialization (nlohmann::json, detail::json_ref)
    nlohmann::json j = {{"pi", 3.141}, {"list", {1, 0, 2}}};
    const nlohmann::ordered_json o = {{"b", 1}, {"a", 2}};

    j["parsed"] = nlohmann::json::parse(R"({"happy": true})");
    j["binary"] = nlohmann::json::binary(std::vector<std::uint8_t> {0xCA, 0xFE}, 42);

    const std::string s = j.dump() + o.dump();
    return s.empty() ? 1 : 0;
}
