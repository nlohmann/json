#include <iostream>
#include <iomanip> // for std::setw
#include "json.hpp"

using json = nlohmann::json;

int main()
{
    // create a JSON value
    json j = R"({"compact": true, "schema": 0})"_json;

    // serialize it to MessagePack
    std::vector<uint8_t> v = json::to_msgpack(j);

    // print the vector content
    for (auto& byte : v)
    {
        std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
    }
    std::cout << std::endl;
}
