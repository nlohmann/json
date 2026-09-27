# nlohmann::basic_json::to_bon8

```
// (1)
static std::vector<std::uint8_t> to_bon8(const basic_json& j);

// (2)
static void to_bon8(const basic_json& j, detail::output_adapter<std::uint8_t> o);
static void to_bon8(const basic_json& j, detail::output_adapter<char> o);
```

Serializes a given JSON value `j` to a byte vector using the BON8 (Binary Object Notation 8) serialization format. BON8 is a compact binary serialization format that stores strings as UTF-8 without a length prefix.

1. Returns a byte vector containing the BON8 serialization.
1. Writes the BON8 serialization to an output adapter.

The exact mapping and its limitations are described on a [dedicated page](https://json.nlohmann.me/features/binary_formats/bon8/index.md).

## Parameters

`j` (in) : JSON value to serialize

`o` (in) : output adapter to write serialization to

## Return value

1. BON8 serialization as a byte vector
1. (none)

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value `j`, which is never modified. With (2), the bytes written before the exception remain in the output adapter.

## Exceptions

- Throws [out_of_range.407](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range407) if `j` contains an unsigned integer above 9223372036854775807, which BON8 cannot represent
- Throws [type_error.316](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error316) if `j` contains a string that is not valid UTF-8

## Complexity

Linear in the size of the JSON value `j`.

## Examples

Example

The example shows the serialization of a JSON value to a byte vector in BON8 format.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace nlohmann::literals;

int main()
{
    // create a JSON value
    json j = R"({"compact": true, "format": "BON8", "schema": 0})"_json;

    // serialize it to BON8
    std::vector<std::uint8_t> v = json::to_bon8(j);

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
0x89 0x63 0x6f 0x6d 0x70 0x61 0x63 0x74 0xf9 0x66 0x6f 0x72 0x6d 0x61 0x74 0xff 0x42 0x4f 0x4e 0x38 0xff 0x73 0x63 0x68 0x65 0x6d 0x61 0x90
```

## See also

- [from_bon8](https://json.nlohmann.me/api/basic_json/from_bon8/index.md) create a JSON value from an input in BON8 format
- [to_cbor](https://json.nlohmann.me/api/basic_json/to_cbor/index.md) create a CBOR serialization of a JSON value
- [to_msgpack](https://json.nlohmann.me/api/basic_json/to_msgpack/index.md) create a MessagePack serialization of a JSON value
- [to_bson](https://json.nlohmann.me/api/basic_json/to_bson/index.md) create a BSON serialization of a JSON value
- [to_ubjson](https://json.nlohmann.me/api/basic_json/to_ubjson/index.md) create a UBJSON serialization of a JSON value
- [to_bjdata](https://json.nlohmann.me/api/basic_json/to_bjdata/index.md) create a BJData serialization of a JSON value

## Version history

- Added in version 3.13.0.
