#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    std::cout << std::boolalpha << std::is_same<nlohmann::byte_container_with_subtype<std::vector<std::uint8_t>>, json::binary_t>::value << std::endl;
}
