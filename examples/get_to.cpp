#include <iostream>
#include <unordered_map>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON value with different types
    json json_types =
    {
        {"boolean", true},
        {
            "number", {
                {"integer", 42},
                {"floating-point", 17.23}
            }
        },
        {"string", "Hello, world!"},
        {"array", {1, 2, 3, 4, 5}},
        {"null", nullptr}
    };

    bool v1;
    int v2;
    short v3;
    float v4;
    int v5;
    std::string v6;
    std::vector<short> v7;
    std::unordered_map<std::string, json> v8;


    // use explicit conversions
    json_types["boolean"].get_to(v1);
    json_types["number"]["integer"].get_to(v2);
    json_types["number"]["integer"].get_to(v3);
    json_types["number"]["floating-point"].get_to(v4);
    json_types["number"]["floating-point"].get_to(v5);
    json_types["string"].get_to(v6);
    json_types["array"].get_to(v7);
    json_types.get_to(v8);

    // print the conversion results
    std::cout << v1 << '\n';
    std::cout << v2 << ' ' << v3 << '\n';
    std::cout << v4 << ' ' << v5 << '\n';
    std::cout << v6 << '\n';

    for (auto i : v7)
    {
        std::cout << i << ' ';
    }
    std::cout << "\n\n";

    for (auto i : v8)
    {
        std::cout << i.first << ": " << i.second << '\n';
    }
}
