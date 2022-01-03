#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    std::cout << std::boolalpha << std::is_same<bool, json::boolean_t>::value << std::endl;
}
