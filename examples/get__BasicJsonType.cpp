#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using ordered_json = nlohmann::ordered_json;

int main()
{
    // create a JSON value
    json j = {{"one", 1}, {"two", 2}, {"three", 3}};

    // convert to a different basic_json specialization
    ordered_json oj = j.get<ordered_json>();

    std::cout << j << '\n';
    std::cout << oj << '\n';
}
