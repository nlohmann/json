#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    std::cout << std::boolalpha << std::is_same<std::map<json::string_t, json>, json::object_t>::value << std::endl;
}
