#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace nlohmann::literals;

int main()
{
    // create a JSON value
    const json j =
    {
        {"number", 1}, {"string", "foo"}, {"array", {1, 2}}
    };

    // read-only access

    // output element with JSON pointer "/number"
    std::cout << j.at("/number"_json_pointer) << '\n';
    // output element with JSON pointer "/string"
    std::cout << j.at("/string"_json_pointer) << '\n';
    // output element with JSON pointer "/array"
    std::cout << j.at("/array"_json_pointer) << '\n';
    // output element with JSON pointer "/array/1"
    std::cout << j.at("/array/1"_json_pointer) << '\n';

    // out_of_range.109
    try
    {
        // try to use an array index that is not a number
        json::const_reference ref = j.at("/array/one"_json_pointer);
    }
    catch (json::parse_error& e)
    {
        std::cout << e.what() << '\n';
    }

    // out_of_range.401
    try
    {
        // try to use an invalid array index
        json::const_reference ref = j.at("/array/4"_json_pointer);
    }
    catch (json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }

    // out_of_range.402
    try
    {
        // try to use the array index '-'
        json::const_reference ref = j.at("/array/-"_json_pointer);
    }
    catch (json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }

    // out_of_range.403
    try
    {
        // try to use a JSON pointer to a nonexistent object key
        json::const_reference ref = j.at("/foo"_json_pointer);
    }
    catch (json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }

    // out_of_range.404
    try
    {
        // try to use a JSON pointer that cannot be resolved
        json::const_reference ref = j.at("/number/foo"_json_pointer);
    }
    catch (json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }
}
