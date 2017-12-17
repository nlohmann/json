#include <iostream>
#include "json.hpp"

using json = nlohmann::json;

int main()
{
    // create a JSON array
    json v = {1, 2, 3, 4};

    // create a JSON array to copy values from
    json v2 = {"one", "two", "three", "four"};

    // insert range from v2 before the end of array v
    auto new_pos = v.insert(v.end(), v2.begin(), v2.end());

    // output new array and result of insert call
    std::cout << *new_pos << '\n';
    std::cout << v << '\n';
}
