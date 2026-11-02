#include <iomanip>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

void print_hex(const char* label, const std::vector<std::uint8_t>& v)
{
    std::cout << label << ':';
    for (auto b : v)
    {
        std::cout << ' ' << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    std::cout << std::dec << std::setfill(' ') << '\n';
}

int main()
{
    // a binary value
    json j = json::binary({0xCA, 0xFE, 0xBA, 0xBE});

    // Draft 2 (the default) writes an array of integers
    auto v2 = json::to_bjdata(j, true, true, json::bjdata_version_t::draft2);
    print_hex("draft2", v2);

    // Draft 3 writes an optimized binary array
    auto v3 = json::to_bjdata(j, true, true, json::bjdata_version_t::draft3);
    print_hex("draft3", v3);

    // reading yields an array for Draft 2 and a binary value for Draft 3
    std::cout << json::from_bjdata(v2) << '\n';
    std::cout << json::from_bjdata(v3) << '\n';
}
