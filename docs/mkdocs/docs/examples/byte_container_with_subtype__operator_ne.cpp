#include <iostream>
#include <nlohmann/json.hpp>

using byte_container_with_subtype = nlohmann::byte_container_with_subtype<std::vector<std::uint8_t>>;

int main()
{
    byte_container_with_subtype c1({0xca, 0xfe});
    byte_container_with_subtype c2({0xca, 0xfe});
    byte_container_with_subtype c3({0xca, 0xfe}, 42);

    std::cout << std::boolalpha
              << "c1 != c2: " << (c1 != c2) << '\n'
              << "c1 != c3: " << (c1 != c3) << std::endl;
}
