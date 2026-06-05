#include <iostream>
#include <string_view>
#include <nlohmann/json.hpp>

using namespace std::string_view_literals;
using json = nlohmann::json;

int main()
{
    // create JSON object
    const json object =
    {
        {"the good", "il buono"},
        {"the bad", "il cattivo"},
        {"the ugly", "il brutto"}
    };

    // output element with key "the ugly" using string_view
    std::cout << object.at("the ugly"sv) << '\n';

    // exception type_error.304
    try
    {
        // use at() with string_view on a non-object type
        const json str = "I am a string";
        std::cout << str.at("the good"sv) << '\n';
    }
    catch (const json::type_error& e)
    {
        std::cout << e.what() << '\n';
    }

    // exception out_of_range.401
    try
    {
        // try to read from a nonexisting key using string_view
        std::cout << object.at("the fast"sv) << '\n';
    }
    catch (const json::out_of_range& e)
    {
        std::cout << "out of range" << '\n';
    }
}
