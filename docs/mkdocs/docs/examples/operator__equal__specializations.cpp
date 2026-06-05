#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    nlohmann::json uj1 = {{"version", 1}, {"type", "integer"}};
    nlohmann::json uj2 = {{"type", "integer"}, {"version", 1}};

    nlohmann::ordered_json oj1 = {{"version", 1}, {"type", "integer"}};
    nlohmann::ordered_json oj2 = {{"type", "integer"}, {"version", 1}};

    std::cout << std::boolalpha << (uj1 == uj2) << '\n' << (oj1 == oj2) << std::endl;
}
