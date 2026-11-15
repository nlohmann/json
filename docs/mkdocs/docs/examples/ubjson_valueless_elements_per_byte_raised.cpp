#include <cstdint>
#include <iostream>
#include <vector>

// accept 16 values per byte of input instead of 4; define the macro before the
// first inclusion of the header, and to the same value in every translation unit
#define JSON_UBJSON_VALUELESS_ELEMENTS_PER_BYTE 16
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// the bytes version 3.12.0 wrote for a table of 1100 rows of 1000 null values
// with to_ubjson(table, true, true): `[$[#I` and the number of rows, then
// `$Z#I` and the number of elements for every row
std::vector<std::uint8_t> table_written_by_3_12_0()
{
    std::vector<std::uint8_t> bytes = {'[', '$', '[', '#', 'I', 1100 >> 8, 1100 & 0xFF};
    for (int row = 0; row < 1100; ++row)
    {
        bytes.insert(bytes.end(), {'$', 'Z', '#', 'I', 1000 >> 8, 1000 & 0xFF});
    }
    return bytes;
}

int main()
{
    // 6607 bytes announce 1,100,000 values, which is below 1,048,576 plus 16
    // for every byte read
    json table = json::from_ubjson(table_written_by_3_12_0());
    std::cout << table.size() << " rows of " << table[0].size() << " values\n";

    // a single container is still limited to 1,048,576 elements
    const std::vector<std::uint8_t> too_long = {'[', '$', 'Z', '#', 'l', 0x00, 0x10, 0x00, 0x01};
    try
    {
        json j = json::from_ubjson(too_long);
    }
    catch (const json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }
}
