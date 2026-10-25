#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using nlohmann::json;

int main()
{
    std::cout << std::boolalpha << std::is_same<double, json::number_float_t>::value << '\n';
}
