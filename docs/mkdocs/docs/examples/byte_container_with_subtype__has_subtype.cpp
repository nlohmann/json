#include <iostream>
#include <nlohmann/json.hpp>

// define a byte container based on std::vector
using byte_container_with_subtype = nlohmann::byte_container_with_subtype<std::vector<std::uint8_t>>;

int main()
{
    std::vector<std::uint8_t> bytes = {{0xca, 0xfe, 0xba, 0xbe}};

    // create container
    auto c1 = byte_container_with_subtype(bytes);

    // create container with subtype
    auto c2 = byte_container_with_subtype(bytes, 42);

    std::cout << std::boolalpha << "c1.has_subtype() = " << c1.has_subtype()
              << "\nc2.has_subtype() = " << c2.has_subtype() << std::endl;
}
