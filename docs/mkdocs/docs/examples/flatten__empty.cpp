#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON value with an empty object and an empty array
    json j =
    {
        {"empty_object", json::object()},
        {"empty_array", json::array()},
        {"name", "Niels"}
    };

    // call flatten()
    json flattened = j.flatten();
    std::cout << std::setw(4) << flattened << "\n\n";

    // the empty containers cannot be restored by unflatten()
    std::cout << std::setw(4) << flattened.unflatten() << '\n';
}
