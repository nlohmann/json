//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

/*
This file implements a test of json_document images suitable for fuzz
testing. The input is used twice:

- as an image: json_document::load() with image_check::full must either throw
  a parse_error or yield a document that serializes to the JSON text it reads
  as; with image_check::bounds, reading and serializing must be safe (checked
  by the sanitizers), and serializing may only throw type_error.316
- as a JSON text: if json_document::parse() accepts it, the image of the
  document must load (with every check) and serialize to the same text

The provided function `LLVMFuzzerTestOneInput` can be used in different fuzzer
drivers.
*/

#include <cassert>
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
using image_check = json_document::image_check;

// see http://llvm.org/docs/LibFuzzer.html
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // the input as an image
    for (const image_check check :
            {
                image_check::full, image_check::bounds
            })
    {
        json_document d;
        try
        {
            d = json_document::load(data, size, check);
        }
        catch (const json::parse_error& e)
        {
            assert(e.id == 116);
            continue;
        }
        std::string dumped;
        try
        {
            dumped = d.root().dump();
        }
        catch (const json::type_error& e)
        {
            // invalid UTF-8 can only pass the bounds check
            assert(check == image_check::bounds && e.id == 316);
            continue;
        }
        const json j = d.root().materialize();
        if (check == image_check::full)
        {
            assert(json::parse(dumped) == j);
            // an image of the loaded document is the input
            assert(d.save() == std::vector<std::uint8_t>(data, data + size));
        }
    }

    // the input as a JSON text
    const std::string text(reinterpret_cast<const char*>(data), size); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    const json_document parsed = json_document::parse(text, false);
    if (!parsed.is_discarded())
    {
        const std::vector<std::uint8_t> image = parsed.save();
        for (const image_check check :
                {
                    image_check::full, image_check::bounds, image_check::none
                })
        {
            const json_document loaded = json_document::load(image, check);
            assert(loaded.root().dump() == parsed.root().dump());
        }
    }
    return 0;
}
