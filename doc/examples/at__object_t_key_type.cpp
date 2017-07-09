#include <iostream>
#include "json.hpp"

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

    // output element with key "the ugly"
    std::cout << object.at("the ugly") << '\n';

    // change element with key "the bad"
    object.at("the bad") = "il cattivo";

    // output changed array
    std::cout << object << '\n';


    // exception type_error.304
    try
    {
        // use at() on a non-object type
        json str = "I am a string";
        str.at("the good") = "Another string";
    }
    catch (json::type_error& e)
    {
        std::cout << e.what() << '\n';
    }

    // exception out_of_range.401
    try
    {
        // try to write at a nonexisting key
        object.at("the fast") = "il rapido";
    }
    catch (json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }
}
