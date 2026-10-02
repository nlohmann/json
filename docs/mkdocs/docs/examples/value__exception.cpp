#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON object with a string value
    json j = {{"name", "the good"}};

    // exception type_error.302
    try
    {
        int v = j.value("name", 0);
        std::cout << v << '\n';
    }
    catch (const json::type_error& e)
    {
        std::cout << e.what() << '\n';
    }

    // exception type_error.306
    try
    {
        json str = "I am a string";
        auto v = str.value("name", 0);
        std::cout << v << '\n';
    }
    catch (const json::type_error& e)
    {
        std::cout << e.what() << '\n';
    }
}
