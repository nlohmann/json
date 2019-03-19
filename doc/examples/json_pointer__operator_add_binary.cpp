#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON pointer
    json::json_pointer ptr("/foo");

    // apppend a JSON Pointer
    std::cout << ptr / json::json_pointer("/bar/baz") << '\n';

    // append a string
    std::cout << ptr / "fob" << '\n';

    // append an array index
    std::cout << ptr / 42 << std::endl;
}
