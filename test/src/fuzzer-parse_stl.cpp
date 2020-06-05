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

    std::map<std::string, uint8_t> mp;
    for(std::size_t i = 1; i < vec.size(); i+=2)
    {
    	int last_entry = static_cast<int>(vec[i-1]);
    	std::string key_str = std::to_string(last_entry);
        std::pair<std::string, uint8_t> insert_data = std::make_pair(key_str, vec[i]);
        mp.insert(insert_data);
    }
    json j_map(mp);
    // iterating json map
    for(json::iterator it = j_map.begin(); it != j_map.end(); ++it)
    {
        auto temp1 = it.key();
        auto temp2 = it.value();
    }

    return 0;
}
