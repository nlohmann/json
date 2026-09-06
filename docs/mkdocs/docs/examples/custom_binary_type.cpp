#include <cstdint>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "custom_binary_type.hpp"

using custom_json = nlohmann::basic_json<std::map, std::vector, std::string, bool,
      std::int64_t, std::uint64_t, double, std::allocator,
      nlohmann::adl_serializer, custom_binary_type>;

int main()
{
    const auto j = custom_json::binary({0x01, 0x02, 0x03});

    std::cout << j.dump() << std::endl;
    std::cout << std::boolalpha << (custom_json::from_cbor(custom_json::to_cbor(j)) == j) << std::endl;
}
