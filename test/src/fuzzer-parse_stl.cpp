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
    json j_vector2 = json::array();
    json j_vector3 = json::array();

    for(std::size_t i = 0; i < j_vector.size(); ++i)
    {
        auto temp = j_vector.at(i);
        // testing at() method
        j_vector2.push_back(temp);
        j_vector3.emplace_back(temp);
        // testing push_back and emplace back methods
    }

    // these three json vectors must be the same
    assert(j_vector == j_vector2);
    assert(j_vector == j_vector3);

    return 0;
}
