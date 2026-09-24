//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cmath> // nan
#include <cstddef> // size_t
#include <cstdint> // int32_t, int64_t, uint32_t, uint64_t
#include <limits> // numeric_limits
#include <random> // mt19937
#include <string> // string, to_string
#include <utility> // move
#include <vector> // vector

#include <nlohmann/json.hpp>

// Values for the round-trip property tests of the UBJSON and BJData writers.
//
// The fuzzer drivers (tests/src/fuzzer-parse_ubjson.cpp and
// fuzzer-parse_bjdata.cpp) check that anything the library parses can be
// serialized, parsed back, and serialized again without loss. Those checks
// only run at OSS-Fuzz, so a regression used to surface days later as an
// external report. The unit tests run the same checks on this corpus in CI.
//
// The corpus is deterministic: std::mt19937's output sequence is fixed by
// the standard, and it is used directly rather than through a distribution
// (whose results are implementation-defined).
namespace utils
{

class round_trip_corpus
{
  public:
    using json = nlohmann::json;

    static std::vector<json> values()
    {
        round_trip_corpus corpus;
        return corpus.build();
    }

    // whether a value contains a binary value, which a BJData or UBJSON round
    // trip may turn into an array of integers
    static bool contains_binary(const json& j)
    {
        if (j.is_binary())
        {
            return true;
        }
        if (j.is_structured())
        {
            for (const auto& element : j)
            {
                if (contains_binary(element))
                {
                    return true;
                }
            }
        }
        return false;
    }

  private:
    std::vector<json> atoms;
    // a fixed seed is the point: the corpus must be the same in every run
    std::mt19937 generator{42}; // NOLINT(cert-msc32-c,cert-msc51-cpp,bugprone-random-generator-seed)

    round_trip_corpus()
    {
        atoms =
        {
            nullptr, true, false,
            // integers at the boundaries of every UBJSON/BJData integer type
            0, 1, -1, 127, 128, 255, 256, -128, -129,
            32767, 32768, 65535, 65536, -32768, -32769,
            (std::numeric_limits<std::int32_t>::min)(), (std::numeric_limits<std::int32_t>::max)(),
            (std::numeric_limits<std::uint32_t>::max)(),
            (std::numeric_limits<std::int64_t>::min)(), (std::numeric_limits<std::int64_t>::max)(),
            static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()) + 1u,
            (std::numeric_limits<std::uint64_t>::max)(),
            // floating-point numbers, including non-finite ones
            0.0, -0.0, 1.5, -2.25, 3.4e38, (std::numeric_limits<double>::max)(),
            std::nan(""), std::numeric_limits<double>::infinity(), -std::numeric_limits<double>::infinity(),
            // strings, including a non-ASCII one and one longer than 255 bytes
            "", "a", "\xC3\xA4", std::string(300, 'x'),
            // binary values with and without subtype
            json::binary({}), json::binary({1, 2, 255}), json::binary({0x80, 0x7F}, 42), json::binary({1}, 0)
        };
    }

    std::vector<json> build()
    {
        std::vector<json> result = atoms;

        // each atom inside containers, including homogeneous ones that the
        // writers encode as optimized (typed) containers
        result.emplace_back(json::array());
        result.emplace_back(json::object());
        for (const auto& atom : atoms)
        {
            result.push_back(json::array({atom}));
            result.push_back(json::array({atom, atom, atom}));
            result.push_back(json::array({json::array({atom})}));
            result.push_back(json::object({{"key", atom}}));
        }
        result.push_back(json::array({1, 1.5}));
        result.push_back(json::array({-1, 255}));
        result.push_back(json::array({"a", "b"}));

        // deep, but well below any recursion or depth limit
        json nested_array = 1;
        json nested_object = 1;
        for (int i = 0; i < 300; ++i)
        {
            nested_array = json::array({nested_array});
            nested_object = json::object({{"key", nested_object}});
        }
        result.push_back(nested_array);
        result.push_back(nested_object);

        add_annotated_arrays(result);
        add_random_values(result);
        return result;
    }

    // objects in the JData annotated array format, which the BJData writer
    // encodes as ND-arrays when the annotation describes a packed array, and
    // as plain objects otherwise (see #5398, #5399, #5403, #5404, and #5542)
    static void add_annotated_arrays(std::vector<json>& result)
    {
        const std::vector<json> types =
        {
            "uint8", "int8", "uint16", "int16", "uint32", "int32", "uint64", "int64",
            "single", "double", "char", "byte", "bool", "unknown", 5, nullptr
        };
        const std::vector<json> sizes =
        {
            json::array(), {3}, {1, 3}, {3, 1}, {2, 3}, {2, 0}, {0, 2}, {2, 2, 2}, {-1, 2}, {2, 1.5},
            "3", 3, nullptr, json::binary({})
        };
        const std::vector<json> data =
        {
            nullptr, 5, "s", json::object({{"a", 1}}), json::array(),
            {1, 2, 3}, {1, 2, 3, 4, 5, 6}, {1, 2, 3, 4, 5, 6, 7, 8},
            {1.5, 2.5, 3.5, 4.5, 5.5, 6.5}, {300, -300, 70000, -70000, 1, 2},
            {"a", "b", "c", "d", "e", "f"}, {json::array({1, 2, 3}), json::array({4, 5, 6})}
        };

        for (const auto& type : types)
        {
            for (const auto& size : sizes)
            {
                for (const auto& d : data)
                {
                    result.push_back({{"_ArrayType_", type}, {"_ArraySize_", size}, {"_ArrayData_", d}});
                }
            }
        }

        // incomplete annotations and annotations with an extra key
        result.push_back({{"_ArraySize_", {2, 3}}, {"_ArrayData_", {1, 2, 3, 4, 5, 6}}});
        result.push_back({{"_ArrayType_", "uint8"}, {"_ArrayData_", {1, 2, 3, 4, 5, 6}}});
        result.push_back({{"_ArrayType_", "uint8"}, {"_ArraySize_", {2, 3}}});
        result.push_back({{"_ArrayType_", "uint8"}, {"_ArraySize_", {2, 3}}, {"_ArrayData_", {1, 2, 3, 4, 5, 6}}, {"extra", 1}});
    }

    // random containers of atoms, both homogeneous and mixed
    void add_random_values(std::vector<json>& result)
    {
        for (int i = 0; i < 1000; ++i)
        {
            result.push_back(random_value(0));
        }
    }

    std::size_t random_below(std::size_t bound)
    {
        return static_cast<std::size_t>(generator()) % bound;
    }

    json random_value(int depth)
    {
        const auto kind = random_below(10);
        if (depth > 3 || kind < 5)
        {
            return atoms[random_below(atoms.size())];
        }

        json result = kind < 8 ? json::array() : json::object();
        const auto count = random_below(5);
        const bool homogeneous = random_below(2) == 0;
        const json fixed = atoms[random_below(atoms.size())];
        for (std::size_t i = 0; i < count; ++i)
        {
            json element = homogeneous ? fixed : random_value(depth + 1);
            if (result.is_array())
            {
                result.push_back(std::move(element));
            }
            else
            {
                result[std::to_string(i)] = std::move(element);
            }
        }
        return result;
    }
};

} // namespace utils
