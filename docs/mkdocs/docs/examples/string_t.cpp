#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using nlohmann::json;

int main()
{
    std::cout << std::boolalpha << std::is_same<std::string, json::string_t>::value << '\n';
}
