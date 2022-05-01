#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    std::cout << std::boolalpha << std::is_same<std::uint64_t, json::number_unsigned_t>::value << std::endl;
}
