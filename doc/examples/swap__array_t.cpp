#include <iostream>
#include "json.hpp"

using json = nlohmann::json;

int main()
{
    // create a JSON value
    json value = {{"array", {1, 2, 3, 4}}};

    // create an array_t
    json::array_t array = {"Snap", "Crackle", "Pop"};

    // swap the array stored in the JSON value
    value["array"].swap(array);

    // output the values
    std::cout << "value = " << value << '\n';
    std::cout << "array = " << array << '\n';
}
