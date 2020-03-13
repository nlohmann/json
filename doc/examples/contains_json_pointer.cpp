#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON value
    json j =
    {
        {"number", 1}, {"string", "foo"}, {"array", {1, 2}}
    };

    std::cout << std::boolalpha
              << j.contains("/number"_json_pointer) << '\n'
              << j.contains("/string"_json_pointer) << '\n'
              << j.contains("/array"_json_pointer) << '\n'
              << j.contains("/array/1"_json_pointer) << '\n'
              << j.contains("/array/-"_json_pointer) << '\n'
              << j.contains("/array/4"_json_pointer) << '\n'
              << j.contains("/baz"_json_pointer) << std::endl;

    // out_of_range.106
    try
    {
        // try to use an array index with leading '0'
        j.contains("/array/01"_json_pointer);
    }
    catch (json::parse_error& e)
    {
        std::cout << e.what() << '\n';
    }

    // out_of_range.109
    try
    {
        // try to use an array index that is not a number
        j.contains("/array/one"_json_pointer);
    }
    catch (json::parse_error& e)
    {
        std::cout << e.what() << '\n';
    }
}
