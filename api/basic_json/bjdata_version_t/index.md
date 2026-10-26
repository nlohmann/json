# nlohmann::basic_json::bjdata_version_t

```
enum class bjdata_version_t
{
    draft2,
    draft3
};
```

This enumeration is used in [`to_bjdata`](https://json.nlohmann.me/api/basic_json/to_bjdata/index.md) to choose the version of the BJData specification to write:

draft2 : BJData Draft 2 (the default). Binary values are written as arrays of `U` integers, and ND-arrays with `"_ArrayType_": "byte"` are written as regular objects, since the `B` marker is not part of Draft 2.

draft3 : BJData Draft 3. Binary values are written as `B` elements: as an optimized binary array (`[$B#`) if both `use_size` and `use_type` are set, and as an array of `B`-prefixed elements otherwise. ND-arrays with `"_ArrayType_": "byte"` are written as packed arrays (`[$B#[...]`).

Only the writer is affected by the version. [`from_bjdata`](https://json.nlohmann.me/api/basic_json/from_bjdata/index.md) reads the markers of both drafts.

## Examples

Example

The example below shows how the different values of the `bjdata_version_t` influence the serialization of a binary value with [`to_bjdata`](https://json.nlohmann.me/api/basic_json/to_bjdata/index.md).

```
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
```

Output:

```
draft2: 5b 24 55 23 69 04 ca fe ba be
draft3: 5b 24 42 23 69 04 ca fe ba be
[202,254,186,190]
{"bytes":[202,254,186,190],"subtype":null}
```

## See also

- [to_bjdata](https://json.nlohmann.me/api/basic_json/to_bjdata/index.md) serializes a JSON value to BJData
- [BJData](https://json.nlohmann.me/features/binary_formats/bjdata/index.md) - the article on the BJData format

## Version history

- Added in version 3.12.0.
