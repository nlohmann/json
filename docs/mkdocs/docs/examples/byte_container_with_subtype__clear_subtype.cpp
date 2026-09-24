#include <iostream>
#include <nlohmann/json.hpp>

// define a byte container based on std::vector
using byte_container_with_subtype = nlohmann::byte_container_with_subtype<std::vector<std::uint8_t>>;

using json = nlohmann::json;

int main()
{
    std::vector<std::uint8_t> bytes = {{0xca, 0xfe, 0xba, 0xbe}};

    // create container with subtype
    auto c1 = byte_container_with_subtype(bytes, 42);

    std::cout << "before calling clear_subtype(): " << json(c1) << '\n';

    c1.clear_subtype();

    std::cout << "after calling clear_subtype(): " << json(c1) << '\n';
}
