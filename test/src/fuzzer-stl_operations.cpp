/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (fuzz test support)
|  |  |__   |  |  | | | |  version 3.7.3
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

This file implements test for stl operations suitable for fuzz testing.

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
    std::unordered_set<uint8_t> uset(data, data + size);
    std::multiset<uint8_t> multist(data, data + size);
    std::unordered_multiset<uint8_t> umultiset(data, data + size);

    // parsing from STL containers
    json j_vector(vec);
    json j_deque(deq);
    json j_list(lst);
    json j_flist(flist);
    json j_set(st);
    json j_uset(uset);
    json j_multiset(multist);
    json j_umultiset(umultiset);

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

    std::map<std::string, uint8_t> mp;
    std::unordered_map<std::string, uint8_t> umap;
    std::multimap<std::string, uint8_t> multimp;
    std::unordered_multimap<std::string, uint8_t> umultimap;

    // converting each consecutive entry in the vector into a key-value pair and adding them to map
    for(std::size_t i = 1; i < vec.size(); i+=2)
    {
    	int last_entry = static_cast<int>(vec[i-1]);
    	std::string key_str = std::to_string(last_entry);
        std::pair<std::string, uint8_t> insert_data = std::make_pair(key_str, vec[i]);
        mp.insert(insert_data);
        umap.insert(insert_data);
        multimp.insert(insert_data);
        umultimap.insert(insert_data);
    }

    // map -> json map
    json j_map(mp);
    json j_umap(umap);
    json j_multimap(multimp);
    json j_umultimap(umultimap);

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
