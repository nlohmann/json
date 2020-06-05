/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (fuzz test support)
|  |  |__   |  |  | | | |  version 3.7.3
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

This file implements a parser test suitable for fuzz testing. Given a byte
array data, it performs the following steps:

- j1 = parse(data)
- s1 = serialize(j1)
- j2 = parse(s1)
- s2 = serialize(j2)
- assert(s1 == s2)

The provided function `LLVMFuzzerTestOneInput` can be used in different fuzzer
drivers.

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
*/

#include <iostream>
#include <deque>
#include <list>
#include <set>
#include <unordered_set>
#include <iterator> 
#include <map>
#include <unordered_map>
#include <utility>
#include <sstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// see http://llvm.org/docs/LibFuzzer.html
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // putting data in several STL containers
    std::vector<uint8_t> vec(data, data + size);

    // parsing from STL containers
    json j_vector(vec);

    try
    {
        // parse input directly
        json j1 = json::parse(data, data + size);
        // parse using vector
        json j_vec = json::parse(vec);

        // both of them must be equal
        assert(j1 == j_vec);
    }
    catch (const json::parse_error&)
    {
        // parse errors are ok, because input may be random bytes
    }
    catch (const json::out_of_range&)
    {
        // out of range errors may happen if provided sizes are excessive
    }

    return 0;
}
