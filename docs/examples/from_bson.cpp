#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create byte vector
    std::vector<std::uint8_t> v = {0x1b, 0x00, 0x00, 0x00, 0x08, 0x63, 0x6f, 0x6d,
                                   0x70, 0x61, 0x63, 0x74, 0x00, 0x01, 0x10, 0x73,
                                   0x63, 0x68, 0x65, 0x6d, 0x61, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00
                                  };

    // deserialize it with BSON
    json j = json::from_bson(v);

    // print the deserialized JSON value
    std::cout << std::setw(2) << j << std::endl;
}
