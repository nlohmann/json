#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create byte vector
    std::vector<std::uint8_t> v = {0x89, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x63, 0x74,
                                   0xf9, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0xff,
                                   0x42, 0x4f, 0x4e, 0x38, 0xff, 0x73, 0x63, 0x68,
                                   0x65, 0x6d, 0x61, 0x90
                                  };

    // deserialize it with BON8
    json j = json::from_bon8(v);

    // print the deserialized JSON value
    std::cout << std::setw(2) << j << std::endl;
}
