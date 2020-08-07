#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a binary value
    json value = json::binary({1, 2, 3});

    // create a binary_t
    json::binary_t binary = {{4, 5, 6}};

    // swap the object stored in the JSON value
    value.swap(binary);

    // output the values
    std::cout << "value = " << value << '\n';
    std::cout << "binary = " << json(binary) << '\n';
}
