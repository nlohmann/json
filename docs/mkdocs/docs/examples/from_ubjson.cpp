#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create byte vector
    std::vector<std::uint8_t> v = {0x7B, 0x69, 0x07, 0x63, 0x6F, 0x6D, 0x70, 0x61,
                                   0x63, 0x74, 0x54, 0x69, 0x06, 0x73, 0x63, 0x68,
                                   0x65, 0x6D, 0x61, 0x69, 0x00, 0x7D
                                  };

    // deserialize it with UBJSON
    json j = json::from_ubjson(v);

    // print the deserialized JSON value
    std::cout << std::setw(2) << j << std::endl;
}
