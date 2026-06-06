// This example demonstrates how to output the JSON library's meta information in a formatted way.

#include <nlohmann/json.hpp>
#include <iostream>
#include <iomanip>

using json = nlohmann::json;

int main()
{
    std::cout << std::setw(4) << json::meta() << std::endl;
}
