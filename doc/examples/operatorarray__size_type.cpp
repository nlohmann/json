#include <iostream>
#include "json.hpp"

using json = nlohmann::json;

int main()
{
    // create a JSON array
    json array = {1, 2, 3, 4, 5};

    // output element at index 3 (fourth element)
    std::cout << array[3] << '\n';

    // change last element to 6
    array[array.size() - 1] = 6;

    // output changed array
    std::cout << array << '\n';

    // write beyond array limit
    array[10] = 11;

    // output changed array
    std::cout << array << '\n';
}
