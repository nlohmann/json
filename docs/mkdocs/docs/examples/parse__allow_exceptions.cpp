#include <iostream>
#include <nlohmann/json.hpp>

using nlohmann::json;

int main()
{
    // an invalid JSON text
    std::string text = R"(
    {
        "key": "value without closing quotes
    }
    )";

    // parse with exceptions
    try
    {
        json j = json::parse(text);
    }
    catch (const json::parse_error& e)
    {
        std::cout << e.what() << '\n';
    }

    // parse without exceptions
    json j = json::parse(text, nullptr, false);

    if (j.is_discarded())
    {
        std::cout << "the input is invalid JSON" << '\n';
    }
    else
    {
        std::cout << "the input is valid JSON: " << j << '\n';
    }
}
