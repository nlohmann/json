#include <iostream>
#include <nlohmann/json.hpp>

// define a byte container based on std::vector
using byte_container_with_subtype = nlohmann::byte_container_with_subtype<std::vector<std::uint8_t>>;

using json = nlohmann::json;

int main()
{
    std::vector<std::uint8_t> bytes = {{0xca, 0xfe, 0xba, 0xbe}};

    // create container without subtype
    auto c = byte_container_with_subtype(bytes);

    std::cout << "before calling set_subtype(42): " << json(c) << '\n';

    // set the subtype
    c.set_subtype(42);

    std::cout << "after calling set_subtype(42): " << json(c) << '\n';
}
