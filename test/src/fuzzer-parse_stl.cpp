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

    // iterating json array and testing get() method
    for(json::iterator it = j_vector.begin(); it != j_vector.end(); ++it)
    {
        try
        {
            int temp = (*it).get<int>();
        }
        catch(const json::type_error)
        {
            // input might not be convertible to integer
        }
    }

    for(auto& element : j_vector)
    {
        // range-based iteration
    }

    json j_vector2;
    json j_vector3;

    for(int i = 0; i < (int)j_vector.size(); ++i)
    {
        auto temp = j_vector.at(i);
        // testing at() method
        j_vector2.push_back(temp);
        j_vector3.emplace_back(temp);
        // testing push_back and emplace back methods
    }

    // these jsons must be the same
    assert(j_vector == j_vector2);
    assert(j_vector == j_vector3);

    std::map<uint8_t, uint8_t> mp;
    std::unordered_map<uint8_t, uint8_t> ump;
    std::multimap<uint8_t, uint8_t> mmp;
    std::unordered_multimap<uint8_t, uint8_t> ummp;

    // converting each consecutive entry in the vector into a key-value pair
    for(int i = 1; i < (int)vec.size(); i+=2)
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

    // iterating json map
    for(json::iterator it = j_map.begin(); it != j_map.end(); ++it)
    {
        auto temp1 = it.key();
        auto temp2 = it.value();
    }

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
    return 0;
}
