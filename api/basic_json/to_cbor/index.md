# nlohmann::basic_json::to_cbor

```
// (1)
static std::vector<std::uint8_t> to_cbor(const basic_json& j);

// (2)
static void to_cbor(const basic_json& j, detail::output_adapter<std::uint8_t> o);
static void to_cbor(const basic_json& j, detail::output_adapter<char> o);
```

Serializes a given JSON value `j` to a byte vector using the CBOR (Concise Binary Object Representation) serialization format. CBOR is a binary serialization format that aims to be more compact than JSON itself, yet more efficient to parse.

1. Returns a byte vector containing the CBOR serialization.
1. Writes the CBOR serialization to an output adapter.

The exact mapping and its limitations are described on a [dedicated page](https://json.nlohmann.me/features/binary_formats/cbor/index.md).

## Parameters

`j` (in) : JSON value to serialize

`o` (in) : output adapter to write serialization to

## Return value

1. CBOR serialization as a byte vector
1. (none)

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Complexity

Linear in the size of the JSON value `j`.

## Examples

Example

The example shows the serialization of a JSON value to a byte vector in CBOR format.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
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
        std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
    }
    std::cout << std::endl;
}
```

Output:

```
0xa2 0x67 0x63 0x6f 0x6d 0x70 0x61 0x63 0x74 0xf5 0x66 0x73 0x63 0x68 0x65 0x6d 0x61 0x00
```

## See also

- [from_cbor](https://json.nlohmann.me/api/basic_json/from_cbor/index.md) create a JSON value from an input in CBOR format
- [to_msgpack](https://json.nlohmann.me/api/basic_json/to_msgpack/index.md) create a MessagePack serialization of a JSON value
- [to_bson](https://json.nlohmann.me/api/basic_json/to_bson/index.md) create a BSON serialization of a JSON value
- [to_ubjson](https://json.nlohmann.me/api/basic_json/to_ubjson/index.md) create a UBJSON serialization of a JSON value
- [to_bjdata](https://json.nlohmann.me/api/basic_json/to_bjdata/index.md) create a BJData serialization of a JSON value

## Version history

- Added in version 2.0.9.
- Compact representation of floating-point numbers added in version 3.8.0.
