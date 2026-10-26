#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using nlohmann::json;

int main()
{
    std::cout << std::boolalpha << std::is_same<std::int64_t, json::number_integer_t>::value << '\n';
}
