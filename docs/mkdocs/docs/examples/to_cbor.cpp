#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using nlohmann::json;
using namespace nlohmann::literals;

int main()
{
    // create a JSON value
    json j = R"({"compact": true, "schema": 0})"_json;

    // serialize it to CBOR
    std::vector<std::uint8_t> v = json::to_cbor(j);

    // print the vector content
    for (auto& byte : v)
    {
        std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
    }
    std::cout << '\n';
}
