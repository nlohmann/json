/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (fuzz test support)
|  |  |__   |  |  | | | |  version 2.0.10
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

This file implements a parser test suitable for fuzz testing. Given a byte
array data, it performs the following steps:

- j1 = from_cbor(data)
- vec = to_cbor(j1)
- j2 = from_cbor(vec)
- assert(j1 == j2)

The provided function `LLVMFuzzerTestOneInput` can be used in different fuzzer
drivers.

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
*/

#include <iostream>
#include <sstream>
#include <json.hpp>

using json = nlohmann::json;

// see http://llvm.org/docs/LibFuzzer.html
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    try
    {
        // step 1: parse input
        std::vector<uint8_t> vec1(data, data + size);
        json j1 = json::from_cbor(vec1);

        try
        {
            // step 2: round trip
            std::vector<uint8_t> vec2 = json::to_cbor(j1);

            // parse serialization
            json j2 = json::from_cbor(vec2);

            // deserializations must match
            assert(j1 == j2);
        }
        catch (const std::invalid_argument&)
        {
            // parsing a CBOR serialization must not fail
            assert(false);
        }
    }
    catch (const std::invalid_argument&)
    {
        // parse errors are ok, because input may be random bytes
    }
    catch (const std::out_of_range&)
    {
        // parse errors are ok, because input may be random bytes
    }
    catch (const std::domain_error&)
    {
        // parse errors are ok, because input may be random bytes
    }

    // return 0 - non-zero return values are reserved for future use
    return 0;
}
