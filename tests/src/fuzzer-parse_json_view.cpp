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
json_view.hpp) agrees with basic_json on every input:

- json_document::accept(data) must equal json::accept(data)
- if the input is accepted, json_document::parse(data).root().materialize()
  must equal json::parse(data)
- if the input is rejected, json_document::parse(data) (with exceptions
  enabled) must throw a json::parse_error or json::out_of_range whose what()
  is identical to the one json::parse(data) throws

The provided function `LLVMFuzzerTestOneInput` can be used in different fuzzer
drivers.
*/

#include <cassert>
#include <string>
#include <nlohmann/json.hpp>
#include <nlohmann/json_view.hpp>

// the checks below are assertions; NDEBUG would compile them away
#ifdef NDEBUG
    #error "the fuzzer drivers must be built without NDEBUG"
#endif

using json = nlohmann::json;
using json_document = nlohmann::json_document;

// see http://llvm.org/docs/LibFuzzer.html
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // json_document::accept only has a single-argument overload; wrap the raw
    // bytes in a (borrowed) std::string so the same bytes can be handed to it
    const std::string input(reinterpret_cast<const char*>(data), size); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)

    const bool accepted_by_json = json::accept(data, data + size);
    const bool accepted_by_view = json_document::accept(input);

    // json_document::accept must agree with json::accept on every input
    assert(accepted_by_json == accepted_by_view);

    if (accepted_by_json)
    {
        // both parsers must agree on the resulting value
        json const j1 = json::parse(data, data + size);
        json_document const doc = json_document::parse(input);
        json const j2 = doc.root().materialize();
        assert(j1 == j2);
    }
    else
    {
        // both parsers must reject the input the same way when exceptions are used
        std::string expected_what;
        bool json_threw = false;
        try
        {
            static_cast<void>(json::parse(data, data + size));
        }
        catch (const json::parse_error& e)
        {
            expected_what = e.what();
            json_threw = true;
        }
        catch (const json::out_of_range& e)
        {
            expected_what = e.what();
            json_threw = true;
        }
        assert(json_threw);

        bool view_threw = false;
        try
        {
            static_cast<void>(json_document::parse(input));
        }
        catch (const json::parse_error& e)
        {
            assert(e.what() == expected_what);
            view_threw = true;
        }
        catch (const json::out_of_range& e)
        {
            assert(e.what() == expected_what);
            view_threw = true;
        }
        assert(view_threw);
    }

    // return 0 - non-zero return values are reserved for future use
    return 0;
}
