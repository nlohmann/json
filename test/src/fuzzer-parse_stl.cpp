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
    return 0;
}
