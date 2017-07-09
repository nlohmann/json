#include <iostream>
#include "json.hpp"

using json = nlohmann::json;

int main()
{
    // create JSON array
    const json array = {"first", "2nd", "third", "fourth"};

    // output element at index 2 (third element)
    std::cout << array.at(2) << '\n';


    // exception type_error.304
    try
    {
        // use at() on a non-array type
        const json str = "I am a string";
        std::cout << str.at(0) << '\n';
    }
    catch (json::type_error& e)
    {
        std::cout << e.what() << '\n';
    }

    // exception out_of_range.401
    try
    {
        // try to read beyond the array limit
        std::cout << array.at(5) << '\n';
    }
    catch (json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }
}
