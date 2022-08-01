#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    json j;
    j["address"]["street"] = "Fake Street";
    j["address"]["housenumber"] = "12";

    try
    {
        int housenumber = j["address"]["housenumber"];
    }
    catch (json::exception& e)
    {
        std::cout << e.what() << '\n';
    }
}
