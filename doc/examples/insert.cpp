#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON array
    json v = {1, 2, 3, 4};

    // insert number 10 before number 3
    auto new_pos = v.insert(v.begin() + 2, 10);

    // output new array and result of insert call
    std::cout << *new_pos << '\n';
    std::cout << v << '\n';
}
