#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    json* j = new json("Hello, world!");
    std::cout << *j << std::endl;

    // explicitly call destructor
    delete j;
}
