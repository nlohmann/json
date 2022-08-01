#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON poiner
    json::json_pointer ptr("/foo/bar/baz");

    // write string representation to stream
    std::cout << ptr << std::endl;
}
