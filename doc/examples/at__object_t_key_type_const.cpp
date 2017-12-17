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


    // exception type_error.304
    try
    {
        // use at() on a non-object type
        const json str = "I am a string";
        std::cout << str.at("the good") << '\n';
    }
    catch (json::type_error& e)
    {
        std::cout << e.what() << '\n';
    }

    // exception out_of_range.401
    try
    {
        // try to read from a nonexisting key
        std::cout << object.at("the fast") << '\n';
    }
    catch (json::out_of_range)
    {
        std::cout << "out of range" << '\n';
    }
}
