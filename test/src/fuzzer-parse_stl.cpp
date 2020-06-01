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
    std::deque<uint8_t> deq(data, data + size);
    std::list<uint8_t> lst(data, data + size);
    std::forward_list<uint8_t> flist(data, data + size);
    std::set<uint8_t> st(data, data + size);
    std::unordered_set<uint8_t> ust(data, data + size);
    std::multiset<uint8_t> mst(data, data + size);
    std::unordered_multiset<uint8_t> umst(data, data + size);

    // parsing from STL containers
    json j_vector(vec);
    json j_deque(deq);
    json j_list(lst);
    json j_flist(flist);
    json j_set(st);
    json j_uset(ust);
    json j_multiset(mst);
    json j_umultiset(umst);

    // json must be same for sequence containers
    assert(j_vector == j_deque);
    assert(j_vector == j_list);
    assert(j_vector == j_flist);

    std::map<uint8_t, uint8_t> mp;
    std::unordered_map<uint8_t, uint8_t> ump;
    std::multimap<uint8_t, uint8_t> mmp;
    std::unordered_multimap<uint8_t, uint8_t> ummp;

    // converting each consecutive entry in the vector into a key-value pair
    for(int i=1; i<size; i+=2)
    {
        std::pair<uint8_t, uint8_t> insert_data = std::make_pair(vec[i-1], vec[i]);
        mp.insert(insert_data);
        ump.insert(insert_data);
        mmp.insert(insert_data);
        ummp.insert(insert_data);
    }

    json j_map(mp);
    json j_umap(ump);
    json j_multimap(mmp);
    json j_umultimap(ummp);

    try
    {
        // parse input directly
        json j1 = json::parse(data, data + size);
        // parse using vector
        json j_vec = json::parse(vec);
        // parse using deque
        json j_deq = json::parse(deq);

        // all three must be equal
        assert(j1 == j_vec);
        assert(j1 == j_deq);
    }
    catch (const json::parse_error&)
    {
        // parse errors are ok, because input may be random bytes
    }
    catch (const json::out_of_range&)
    {
        // out of range errors may happen if provided sizes are excessive
    }
    // try
    // {
    //     // step 1: parse input
    //     json j1 = json::parse(data, data + size);

    //     try
    //     {
    //         // step 2: round trip

    //         // first serialization
    //         std::string s1 = j1.dump();

    //         // parse serialization
    //         json j2 = json::parse(s1);

    //         // second serialization
    //         std::string s2 = j2.dump();

    //         // serializations must match
    //         assert(s1 == s2);
    //     }
    //     catch (const json::parse_error&)
    //     {
    //         // parsing a JSON serialization must not fail
    //         assert(false);
    //     }
    // }
    // catch (const json::parse_error&)
    // {
    //     // parse errors are ok, because input may be random bytes
    // }
    // catch (const json::out_of_range&)
    // {
    //     // out of range errors may happen if provided sizes are excessive
    // }

    // return 0 - non-zero return values are reserved for future use
    return 0;
}
