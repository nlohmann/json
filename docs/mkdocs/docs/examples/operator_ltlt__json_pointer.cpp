#include <iostream>
#include <nlohmann/json.hpp>

using nlohmann::json;

int main()
{
    // create JSON pointer
    json::json_pointer ptr("/foo/bar/baz");

    // write string representation to stream
    std::cout << ptr << '\n';
}
