#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON value
    const json j =
    {
        {"number", 1}, {"string", "foo"}, {"array", {1, 2}}
    };

    // read-only access

    // output element with JSON pointer "/number"
    std::cout << j["/number"_json_pointer] << '\n';
    // output element with JSON pointer "/string"
    std::cout << j["/string"_json_pointer] << '\n';
    // output element with JSON pointer "/array"
    std::cout << j["/array"_json_pointer] << '\n';
    // output element with JSON pointer "/array/1"
    std::cout << j["/array/1"_json_pointer] << '\n';
}
