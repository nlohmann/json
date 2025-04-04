#include <iostream>
#include <nlohmann/json.hpp>

// define a byte container based on std::vector
using byte_container_with_subtype = nlohmann::byte_container_with_subtype<std::vector<std::uint8_t>>;

using json = nlohmann::json;

int main()
{
    // (1) create empty container
    auto c1 = byte_container_with_subtype();

    std::vector<std::uint8_t> bytes = {{0xca, 0xfe, 0xba, 0xbe}};

    // (2) create container
    auto c2 = byte_container_with_subtype(bytes);

    // (3) create container with subtype
    auto c3 = byte_container_with_subtype(bytes, 42);

    std::cout << json(c1) << "\n" << json(c2) << "\n" << json(c3) << std::endl;
}
