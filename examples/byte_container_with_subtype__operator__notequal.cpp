#include <iostream>
#include <nlohmann/json.hpp>

// define a byte container based on std::vector
using byte_container_with_subtype = nlohmann::byte_container_with_subtype<std::vector<std::uint8_t>>;

int main()
{
    std::vector<std::uint8_t> bytes = {{0xca, 0xfe, 0xba, 0xbe}};

    // create containers without and with a subtype
    auto c1 = byte_container_with_subtype(bytes);
    auto c2 = byte_container_with_subtype(bytes);
    auto c3 = byte_container_with_subtype(bytes, 42);
    auto c4 = byte_container_with_subtype(bytes, 42);
    auto c5 = byte_container_with_subtype(bytes, 23);

    std::cout << std::boolalpha
              << "c1 != c2: " << (c1 != c2) << '\n'
              << "c1 != c3: " << (c1 != c3) << '\n'
              << "c3 != c4: " << (c3 != c4) << '\n'
              << "c3 != c5: " << (c3 != c5) << std::endl;
}
