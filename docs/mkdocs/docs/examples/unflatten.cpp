#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON value
    json j_flattened =
    {
        {"/answer/everything", 42},
        {"/happy", true},
        {"/list/0", 1},
        {"/list/1", 0},
        {"/list/2", 2},
        {"/name", "Niels"},
        {"/nothing", nullptr},
        {"/object/currency", "USD"},
        {"/object/value", 42.99},
        {"/pi", 3.141}
    };

    // call unflatten()
    std::cout << std::setw(4) << j_flattened.unflatten() << '\n';
}
