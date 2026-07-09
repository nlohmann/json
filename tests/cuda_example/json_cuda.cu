//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include <nlohmann/json.hpp>

int main()
{
    nlohmann::ordered_json json = {"Test"};
    json.dump();

    // regression for #3013 (ordered_json::reset() compile error with nvcc)
    nlohmann::ordered_json metadata;
    metadata.erase("key");

    // exercise comparisons (operator==/operator<=>, gated by
    // JSON_HAS_THREE_WAY_COMPARISON, independent of JSON_HAS_RANGES) and
    // range-based iteration (exercises iteration_proxy/ranges machinery
    // beyond just the enable_borrowed_range specialization) — see #3907
    nlohmann::json a = {1, 2, 3};
    nlohmann::json b = {1, 2, 3};
    static_cast<void>(a == b);
#if JSON_HAS_THREE_WAY_COMPARISON
    static_cast<void>(a <=> b); // *NOPAD*
    static_cast<void>(a <=> 1); // *NOPAD*
#endif
    for (const auto& element : a)
    {
        static_cast<void>(element);
    }
}
