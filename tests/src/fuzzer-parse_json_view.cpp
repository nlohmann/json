//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

/*
This file implements a parser test suitable for fuzz testing. It checks that
json_document (the zero-copy, read-only view of a parsed JSON text declared in
json_view.hpp) agrees with basic_json on every input, for the parse options
selected by the low bits of the first input byte (bit 0: ignore_comments, bit 1:
ignore_trailing_commas; the byte stays part of the text):

- json_document::accept(data) must equal json::accept(data)
- if the input is accepted, json_document::parse(data).root().materialize()
  must equal json::parse(data)
- if the input is rejected, json_document::parse(data) (with exceptions
  enabled) must throw a json::parse_error or json::out_of_range whose what()
  is identical to the one json::parse(data) throws

This is checked for two kinds of input: a std::string, which the document
borrows and which ends in the NUL the parser uses as sentinel, and an
exact-size byte vector, which has no NUL after its last byte and takes the
parser's bounds-checked path (AddressSanitizer reports any read past the end).

The provided function `LLVMFuzzerTestOneInput` can be used in different fuzzer
drivers.
*/

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include <nlohmann/json_view.hpp>

// the checks below are assertions; NDEBUG would compile them away
#ifdef NDEBUG
    #error "the fuzzer drivers must be built without NDEBUG"
#endif

using json = nlohmann::json;
using json_document = nlohmann::json_document;

namespace
{
// what json::parse does with a text: the value, or the message of the exception
struct reference_result
{
    bool accepted = false;
    json value{};
    std::string what{}; // NOLINT(readability-redundant-member-init)
};

reference_result parse_reference(const std::uint8_t* data, std::size_t size, bool comments, bool trailing_commas)
{
    reference_result r;
    r.accepted = json::accept(data, data + size, comments, trailing_commas);
    bool json_threw = false;
    try
    {
        r.value = json::parse(data, data + size, nullptr, true, comments, trailing_commas);
    }
    catch (const json::parse_error& e)
    {
        r.what = e.what();
        json_threw = true;
    }
    catch (const json::out_of_range& e)
    {
        r.what = e.what();
        json_threw = true;
    }
    // json::accept and json::parse must agree
    assert(json_threw == !r.accepted);
    static_cast<void>(json_threw);
    return r;
}

// json_document must agree with the reference for this input (a container
// that json_document::parse borrows)
template<typename Input>
void check_input(const Input& input, const reference_result& expected, bool comments, bool trailing_commas)
{
    // json_document::accept must agree with json::accept on every input
    const bool accepted_by_view = json_document::accept(input, comments, trailing_commas);
    assert(expected.accepted == accepted_by_view);
    static_cast<void>(accepted_by_view);

    if (expected.accepted)
    {
        // both parsers must agree on the resulting value
        json_document const doc = json_document::parse(input, true, comments, trailing_commas);
        assert(!doc.is_discarded());
        json const j2 = doc.root().materialize();
        assert(expected.value == j2);
        static_cast<void>(j2);

        // (without exceptions, the same document)
        json_document const quiet = json_document::parse(input, false, comments, trailing_commas);
        assert(!quiet.is_discarded());
        assert(quiet.node_count() == doc.node_count());
    }
    else
    {
        // both parsers must reject the input the same way when exceptions are used
        bool view_threw = false;
        try
        {
            static_cast<void>(json_document::parse(input, true, comments, trailing_commas));
        }
        catch (const json::parse_error& e)
        {
            assert(e.what() == expected.what);
            view_threw = true;
        }
        catch (const json::out_of_range& e)
        {
            assert(e.what() == expected.what);
            view_threw = true;
        }
        assert(view_threw);
        static_cast<void>(view_threw);

        // and without exceptions, the document is discarded
        json_document const quiet = json_document::parse(input, false, comments, trailing_commas);
        assert(quiet.is_discarded());
        static_cast<void>(quiet);
    }
}
} // namespace

// see http://llvm.org/docs/LibFuzzer.html
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // the parse options are taken from the low bits of the first byte
    const bool comments = size > 0 && (data[0] & 1U) != 0;
    const bool trailing_commas = size > 0 && (data[0] & 2U) != 0;

    const reference_result expected = parse_reference(data, size, comments, trailing_commas);

    // a std::string: borrowed, with the NUL of std::string as sentinel
    const std::string input(reinterpret_cast<const char*>(data), size); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    check_input(input, expected, comments, trailing_commas);

    // an exact-size byte vector: borrowed, with nothing after its last byte
    const std::vector<std::uint8_t> exact(data, data + size);
    check_input(exact, expected, comments, trailing_commas);

    // return 0 - non-zero return values are reserved for future use
    return 0;
}
