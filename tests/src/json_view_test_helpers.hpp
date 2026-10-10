//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

// helpers shared by the unit-json_view*.cpp files, which are split to keep every
// object file small enough for the MinGW linker (it fails to link objects with
// more than 32767 sections)

#include <nlohmann/json_view.hpp>

#include <algorithm> // any_of
#include <functional> // function
#include <random> // mt19937
#include <string> // string

namespace json_view_test
{
// a small deterministic generator of documents
struct generator
{
    std::mt19937 rng{5295}; // NOLINT(cert-msc32-c,cert-msc51-cpp,bugprone-random-generator-seed)

    int r(int n)
    {
        return static_cast<int>(rng() % static_cast<unsigned>(n));
    }

    void str(std::string& o)
    {
        static const char* const pieces[] = {"a", "Z", " ", "\\n", "\\\"", "\\u00e9", "\\ud83d\\ude00", "\xc3\xa9", "\xe3\x81\x82", "long text beyond the first sixteen bytes"}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        o += '"';
        for (int n = r(5); n > 0; --n)
        {
            o += pieces[r(10)];
        }
        o += '"';
    }

    void value(std::string& o, int depth)
    {
        static const char* const scalars[] = {"0", "-1", "123456789012", "18446744073709551615", "18446744073709551616", "-9223372036854775809", // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
                                              "1.5", "-2.25e-3", "1E2", "0.1", "true", "false", "null"
                                             };
        const int k = depth > 5 ? 2 + r(4) : r(6);
        if (k < 2)
        {
            const bool object = k == 0;
            o += object ? '{' : '[';
            for (int i = r(5); i > 0; --i)
            {
                if (object)
                {
                    str(o);
                    o += r(2) == 0 ? ":" : " : ";
                }
                value(o, depth + 1);
                o += i > 1 ? ", " : "";
            }
            o += object ? '}' : ']';
        }
        else if (k < 4)
        {
            str(o);
        }
        else
        {
            o += scalars[r(13)];
        }
    }
};

// whether an object of the view repeats a key
inline bool has_duplicate_keys(const nlohmann::ordered_json_view& v)
{
    if (v.is_object() && v.size() != v.materialize().size())
    {
        return true;
    }
    return std::any_of(v.begin(), v.end(), [](const nlohmann::ordered_json_view e)
    {
        return e.is_structured() && has_duplicate_keys(e);
    });
}

#if !defined(JSON_NOEXCEPTION)
// the exception a call throws, or "" if it throws none
inline std::string exception_of_call(const std::function<void()>& f)
{
    try
    {
        f();
    }
    catch (const nlohmann::json::exception& e)
    {
        return e.what();
    }
    return "";
}
#endif
} // namespace json_view_test
