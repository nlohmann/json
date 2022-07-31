#include <iostream>
#include <string_view>
#include <nlohmann/json.hpp>

using namespace std::string_view_literals;
using json = nlohmann::json;

int main()
{
    // create JSON object
    json object =
    {
        {"the good", "il buono"},
        {"the bad", "il cattivo"},
        {"the ugly", "il brutto"}
    };

    // output element with key "the ugly" using string_view
    std::cout << object.at("the ugly"sv) << '\n';

    // change element with key "the bad" using string_view
    object.at("the bad"sv) = "il cattivo";

    // output changed array
    std::cout << object << '\n';


    // exception type_error.304
    try
    {
        // use at() with string_view on a non-object type
        json str = "I am a string";
        str.at("the good"sv) = "Another string";
    }
    catch (json::type_error& e)
    {
        std::cout << e.what() << '\n';
    }

    // exception out_of_range.401
    try
    {
        // try to write at a nonexisting key using string_view
        object.at("the fast"sv) = "il rapido";
    }
    catch (json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }
}
