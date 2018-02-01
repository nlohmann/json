#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON object with different entry types
    json j =
    {
        {"integer", 1},
        {"floating", 42.23},
        {"string", "hello world"},
        {"boolean", true},
        {"object", {{"key1", 1}, {"key2", 2}}},
        {"array", {1, 2, 3}}
    };

    // access existing values
    int v_integer = j.value("/integer"_json_pointer, 0);
    double v_floating = j.value("/floating"_json_pointer, 47.11);

    // access nonexisting values and rely on default value
    std::string v_string = j.value("/nonexisting"_json_pointer, "oops");
    bool v_boolean = j.value("/nonexisting"_json_pointer, false);

    // output values
    std::cout << std::boolalpha << v_integer << " " << v_floating
              << " " << v_string << " " << v_boolean << "\n";
}
