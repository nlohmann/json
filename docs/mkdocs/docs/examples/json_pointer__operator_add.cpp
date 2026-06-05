#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON pointer
    json::json_pointer ptr("/foo");
    std::cout << "\"" << ptr << "\"\n";

    // append a JSON Pointer
    ptr /= json::json_pointer("/bar/baz");
    std::cout << "\"" << ptr << "\"\n";

    // append a string
    ptr /= "fob";
    std::cout << "\"" << ptr << "\"\n";

    // append an array index
    ptr /= 42;
    std::cout << "\"" << ptr << "\"" << std::endl;
}
