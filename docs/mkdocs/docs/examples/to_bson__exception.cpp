#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON object whose key contains a null byte (U+0000)
    std::string key = "ab";
    key.push_back('\0');
    key.push_back('c');
    json j = {{key, 1}};

    // exception out_of_range.409
    try
    {
        json::to_bson(j);
    }
    catch (const json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }
}
