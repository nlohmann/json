#include <cstdint>
#include <iostream>
#include <vector>
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
    try
    {
        // 6607 bytes announce 1,100,000 values, more than 1,048,576 plus 4 for
        // every byte read (the limit is exceeded in row 1075)
        json table = json::from_ubjson(table_written_by_3_12_0());
        std::cout << table.size() << " rows\n";
    }
    catch (const json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }
}
