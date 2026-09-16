#include <iostream>
#include <nlohmann/json.hpp>

using byte_container_with_subtype = nlohmann::byte_container_with_subtype<std::vector<std::uint8_t>>;

int main()
{
    std::cout << std::boolalpha
              << std::is_same<byte_container_with_subtype::subtype_type, std::uint64_t>::value << std::endl;
}
