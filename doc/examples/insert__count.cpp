#include <iostream>
#include "json.hpp"

using json = nlohmann::json;

int main()
{
    // create a JSON array
    json v = {1, 2, 3, 4};

    // insert number 7 copies of number 7 before number 3
    auto new_pos = v.insert(v.begin() + 2, 7, 7);

    // output new array and result of insert call
    std::cout << *new_pos << '\n';
    std::cout << v << '\n';
}
