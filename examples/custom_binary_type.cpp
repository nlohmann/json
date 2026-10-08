#include <iostream>

#include <nlohmann/json.hpp>

#include "custom_binary_type.hpp"

using custom_json = nlohmann::json::with_binary_t<custom_binary_type>;

int main()
{
    const auto j = custom_json::binary({0x01, 0x02, 0x03});

    std::cout << j.dump() << std::endl;
    std::cout << std::boolalpha << (custom_json::from_cbor(custom_json::to_cbor(j)) == j) << std::endl;
}
