# nlohmann::basic_json::to_bson

```
// (1)
static std::vector<std::uint8_t> to_bson(const basic_json& j);

// (2)
static void to_bson(const basic_json& j, detail::output_adapter<std::uint8_t> o);
static void to_bson(const basic_json& j, detail::output_adapter<char> o);
```

BSON (Binary JSON) is a binary format in which zero or more ordered key/value pairs are stored as a single entity (a so-called document).

1. Returns a byte vector containing the BSON serialization.
1. Writes the BSON serialization to an output adapter.

The exact mapping and its limitations are described on a [dedicated page](https://json.nlohmann.me/features/binary_formats/bson/index.md).

## Parameters

`j` (in) : JSON value to serialize

`o` (in) : output adapter to write serialization to

## Return value

1. BSON serialization as a byte vector
1. (none)

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

- Throws [`type_error.317`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error317) if the top-level type of the JSON value is not an object; example: `"to serialize to BSON, top-level type must be object, but is string"`
- Throws [`out_of_range.409`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range409) if a key in the JSON object contains a null byte (code point U+0000); example: `"BSON key cannot contain code point U+0000 (at byte 2)"`

## Complexity

Linear in the size of the JSON value `j`.

## Examples

Example

The example shows the serialization of a JSON value to a byte vector in BSON format.

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

    // serialize it to BSON
    std::vector<std::uint8_t> v = json::to_bson(j);

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
0x1b 0x00 0x00 0x00 0x08 0x63 0x6f 0x6d 0x70 0x61 0x63 0x74 0x00 0x01 0x10 0x73 0x63 0x68 0x65 0x6d 0x61 0x00 0x00 0x00 0x00 0x00 0x00
```

## See also

- [from_bson](https://json.nlohmann.me/api/basic_json/from_bson/index.md) create a JSON value from an input in BSON format
- [to_cbor](https://json.nlohmann.me/api/basic_json/to_cbor/index.md) create a CBOR serialization of a JSON value
- [to_msgpack](https://json.nlohmann.me/api/basic_json/to_msgpack/index.md) create a MessagePack serialization of a JSON value
- [to_ubjson](https://json.nlohmann.me/api/basic_json/to_ubjson/index.md) create a UBJSON serialization of a JSON value
- [to_bjdata](https://json.nlohmann.me/api/basic_json/to_bjdata/index.md) create a BJData serialization of a JSON value

## Version history

- Added in version 3.4.0.
