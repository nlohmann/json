#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    std::string s = R"(
    {
        "planets": [
            "Mercury",
            "Venus",
            "Earth",
            "Mars",
            "Jupiter",
            "Uranus",
            "Neptune",
        ]
    }
    )";

    try
    {
        json j = json::parse(s);
    }
    catch (json::exception& e)
    {
        std::cout << e.what() << std::endl;
    }

    json j = json::parse(s,
                         /* callback */ nullptr,
                         /* allow exceptions */ true,
                         /* ignore_comments */ false,
                         /* ignore_trailing_commas */ true);
    std::cout << j.dump(2) << '\n';
}
