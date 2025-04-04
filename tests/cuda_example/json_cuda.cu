//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.11.3
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013 - 2025 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include <nlohmann/json.hpp>

int main()
{
    nlohmann::ordered_json json = {"Test"};
    json.dump();

    // regression for #3013 (ordered_json::reset() compile error with nvcc)
    nlohmann::ordered_json metadata;
    metadata.erase("key");
}
