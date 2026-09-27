# nlohmann::basic_json::to_msgpack

```
// (1)
static std::vector<std::uint8_t> to_msgpack(const basic_json& j);

// (2)
static void to_msgpack(const basic_json& j, detail::output_adapter<std::uint8_t> o);
static void to_msgpack(const basic_json& j, detail::output_adapter<char> o);
```

Serializes a given JSON value `j` to a byte vector using the MessagePack serialization format. MessagePack is a binary serialization format that aims to be more compact than JSON itself, yet more efficient to parse.

1. Returns a byte vector containing the MessagePack serialization.
1. Writes the MessagePack serialization to an output adapter.

The exact mapping and its limitations are described on a [dedicated page](https://json.nlohmann.me/features/binary_formats/messagepack/index.md).

## Parameters

`j` (in) : JSON value to serialize

`o` (in) : output adapter to write serialization to

## Return value

1. MessagePack serialization as a byte vector
1. (none)

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

- Throws [`out_of_range.412`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range412) if the length of a string, binary value, array, or object exceeds 4294967295, the maximum MessagePack can store; example: `"MessagePack length 4294967296 exceeds maximum of 4294967295"`
- Throws [`out_of_range.415`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range415) if the subtype of a binary value exceeds 255, the maximum of the MessagePack ext type; example: `"subtype 70000 is too large for the MessagePack ext type (max 255)"`

## Complexity

Linear in the size of the JSON value `j`.

## Examples

Example

The example shows the serialization of a JSON value to a byte vector in MessagePack format.

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

    // serialize it to MessagePack
    std::vector<std::uint8_t> v = json::to_msgpack(j);

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
0x82 0xa7 0x63 0x6f 0x6d 0x70 0x61 0x63 0x74 0xc3 0xa6 0x73 0x63 0x68 0x65 0x6d 0x61 0x00
```

## See also

- [from_msgpack](https://json.nlohmann.me/api/basic_json/from_msgpack/index.md) create a JSON value from an input in MessagePack format
- [to_cbor](https://json.nlohmann.me/api/basic_json/to_cbor/index.md) create a CBOR serialization of a JSON value
- [to_bson](https://json.nlohmann.me/api/basic_json/to_bson/index.md) create a BSON serialization of a JSON value
- [to_ubjson](https://json.nlohmann.me/api/basic_json/to_ubjson/index.md) create a UBJSON serialization of a JSON value
- [to_bjdata](https://json.nlohmann.me/api/basic_json/to_bjdata/index.md) create a BJData serialization of a JSON value

## Version history

- Added in version 2.0.9.
- Throws `out_of_range.412` and `out_of_range.415` since version 3.13.0.
