#include <iostream>
#include "json.hpp"

using json = nlohmann::json;

int main()
{
    // create a JSON value
    json j =
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

    // writing access

    // change the string
    j["/string"_json_pointer] = "bar";
    // output the changed string
    std::cout << j["string"] << '\n';

    // "change" a nonexisting object entry
    j["/boolean"_json_pointer] = true;
    // output the changed object
    std::cout << j << '\n';

    // change an array element
    j["/array/1"_json_pointer] = 21;
    // "change" an array element with nonexisting index
    j["/array/4"_json_pointer] = 44;
    // output the changed array
    std::cout << j["array"] << '\n';

    // "change" the array element past the end
    j["/array/-"_json_pointer] = 55;
    // output the changed array
    std::cout << j["array"] << '\n';
}
