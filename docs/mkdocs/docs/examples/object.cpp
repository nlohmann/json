#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON objects
    json j_no_init_list = json::object();
    json j_empty_init_list = json::object({});
    json j_list_of_pairs = json::object({ {"one", 1}, {"two", 2} });

    // serialize the JSON objects
    std::cout << j_no_init_list << '\n';
    std::cout << j_empty_init_list << '\n';
    std::cout << j_list_of_pairs << '\n';

    // example for an exception
    try
    {
        // can only create an object from a list of pairs
        json j_invalid_object = json::object({{ "one", 1, 2 }});
    }
    catch (const json::type_error& e)
    {
        std::cout << e.what() << '\n';
    }
}
