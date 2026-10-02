#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON string that is not valid UTF-8
    std::string invalid_utf8;
    invalid_utf8.push_back(static_cast<char>(0xFF));
    json j = invalid_utf8;

    // exception type_error.316
    try
    {
        json::to_bon8(j);
    }
    catch (const json::type_error& e)
    {
        std::cout << e.what() << '\n';
    }
}
