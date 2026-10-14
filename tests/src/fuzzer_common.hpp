//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// code shared by the fuzzer drivers tests/src/fuzzer-parse_*.cpp

#pragma once

#include <cassert> // assert
#include <cstddef> // size_t
#include <cstdint> // uint8_t
#include <cstdio> // FILE, fmemopen, fclose
#include <list> // list
#include <sstream> // istringstream
#include <string> // string
#include <utility> // forward
#include <vector> // vector
#include <nlohmann/json.hpp>

using nlohmann::json; // NOLINT(google-global-names-in-headers): shared by all fuzzer drivers

// the round-trip checks of the drivers are assertions; NDEBUG would compile them away
#ifdef NDEBUG
    #error "the fuzzer drivers must be built without NDEBUG"
#endif

// compares dumps rather than values, because NaN != NaN; keep writes strings
// byte for byte, so ill-formed UTF-8 that a binary reader accepts cannot throw
inline bool same_value(const json& lhs, const json& rhs)
{
    return lhs.dump(-1, ' ', false, json::error_handler_t::keep) == rhs.dump(-1, ' ', false, json::error_handler_t::keep);
}

// step 0 of each driver: parse the input without exceptions; a parse error
// must then be reported as a discarded value, never thrown. Type and
// out-of-range errors are not parse errors and still throw; then @a threw is
// set and null is returned.
template<typename Parse>
json parse_without_exceptions(Parse parse, bool& threw)
{
    threw = false;
    try
    {
        return parse();
    }
    catch (const json::parse_error&)
    {
        assert(false);
    }
    catch (const json::exception&)
    {
        threw = true;
    }
    return {};
}

// the outcome of reading an input with exceptions: the serialization of the
// value, or the id, message, and (for parse errors) byte of the exception
struct read_outcome
{
    std::string value{};
    int id = 0;
    std::string what{};
    std::size_t byte = 0;

    bool operator==(const read_outcome& rhs) const
    {
        return value == rhs.value && id == rhs.id && what == rhs.what && byte == rhs.byte;
    }
};

inline std::string outcome_value(const json& j)
{
    return j.dump(-1, ' ', false, json::error_handler_t::keep);
}

inline std::string outcome_value(bool b)
{
    return b ? "true" : "false";
}

template<typename Read, typename... Args>
read_outcome read_with(const Read& parse, Args&& ... args)
{
    read_outcome result;
    try
    {
        result.value = outcome_value(parse(std::forward<Args>(args)...));
    }
    catch (const json::parse_error& e)
    {
        result.id = e.id;
        result.what = e.what();
        result.byte = e.byte;
    }
    catch (const json::exception& e)
    {
        result.id = e.id;
        result.what = e.what();
    }
    return result;
}

// The contiguous input (a pointer range) takes the bulk fast paths; the other
// input adapters read byte by byte. Reads @a data through each of them and
// checks that all give the same value, or the same exception with the same
// id, message, and byte position.
//
// @a parse is called with either an iterator range or a single input (stream
// or FILE*) and returns the parsed value (or the result of accept()).
template<typename Read>
void check_input_adapters(const std::uint8_t* data, std::size_t size, const Read& parse)
{
    const read_outcome expected = read_with(parse, data, data + size);

    // stream adapter
    {
        std::istringstream stream(std::string(reinterpret_cast<const char*>(data), size));
        assert(read_with(parse, stream) == expected);
    }

    // iterator adapter on a non-contiguous range
    {
        const std::list<std::uint8_t> list(data, data + size);
        assert(read_with(parse, list.begin(), list.end()) == expected);
    }

#if defined(__unix__) || defined(__APPLE__)
    // FILE* adapter; fmemopen may refuse an empty buffer
    {
        std::vector<std::uint8_t> buffer(data, data + size);
        std::FILE* file = buffer.empty() ? nullptr : fmemopen(buffer.data(), buffer.size(), "rb");
        if (file != nullptr)
        {
            const read_outcome actual = read_with(parse, file);
            std::fclose(file);
            assert(actual == expected);
        }
    }
#endif
}
