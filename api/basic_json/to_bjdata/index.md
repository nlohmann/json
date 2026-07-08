# nlohmann::basic_json::to_bjdata

```
// (1)
static std::vector<std::uint8_t> to_bjdata(const basic_json& j,
                                           const bool use_size = false,
                                           const bool use_type = false,
                                           const bjdata_version_t version = bjdata_version_t::draft2);

// (2)
static void to_bjdata(const basic_json& j, detail::output_adapter<std::uint8_t> o,
                      const bool use_size = false, const bool use_type = false,
                      const bjdata_version_t version = bjdata_version_t::draft2);
static void to_bjdata(const basic_json& j, detail::output_adapter<char> o,
                      const bool use_size = false, const bool use_type = false,
                      const bjdata_version_t version = bjdata_version_t::draft2);
```

Serializes a given JSON value `j` to a byte vector using the BJData (Binary JData) serialization format. BJData aims to be more compact than JSON itself, yet more efficient to parse.

1. Returns a byte vector containing the BJData serialization.
1. Writes the BJData serialization to an output adapter.

The exact mapping and its limitations are described on a [dedicated page](https://json.nlohmann.me/features/binary_formats/bjdata/index.md).

## Parameters

`j` (in) : JSON value to serialize

`o` (in) : output adapter to write serialization to

`use_size` (in) : whether to add size annotations to container types; optional, `false` by default.

`use_type` (in) : whether to add type annotations to container types (must be combined with `use_size = true`); optional, `false` by default.

`version` (in) : which version of BJData to use (see note on "Binary values" on [BJData](https://json.nlohmann.me/features/binary_formats/bjdata/index.md)); optional, `bjdata_version_t::draft2` by default.

## Return value

1. BJData serialization as byte vector
1. (none)

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Complexity

Linear in the size of the JSON value `j`.

## Examples

Example

The example shows the serialization of a JSON value to a byte vector in BJData format.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace nlohmann::literals;

// function to print BJData's diagnostic format
void print_byte(uint8_t byte)
{
    if (32 < byte and byte < 128)
    {
        std::cout << (char)byte;
    }
    else
    {
        std::cout << (int)byte;
    }
}

int main()
{
    // create a JSON value
    json j = R"({"compact": true, "schema": false})"_json;

    // serialize it to BJData
    std::vector<std::uint8_t> v = json::to_bjdata(j);

    // print the vector content
    for (auto& byte : v)
    {
        print_byte(byte);
    }
    std::cout << std::endl;

    // create an array of numbers
    json array = {1, 2, 3, 4, 5, 6, 7, 8};

    // serialize it to BJData using default representation
    std::vector<std::uint8_t> v_array = json::to_bjdata(array);
    // serialize it to BJData using size optimization
    std::vector<std::uint8_t> v_array_size = json::to_bjdata(array, true);
    // serialize it to BJData using type optimization
    std::vector<std::uint8_t> v_array_size_and_type = json::to_bjdata(array, true, true);

    // print the vector contents
    for (auto& byte : v_array)
    {
        print_byte(byte);
    }
    std::cout << std::endl;

    for (auto& byte : v_array_size)
    {
        print_byte(byte);
    }
    std::cout << std::endl;

    for (auto& byte : v_array_size_and_type)
    {
        print_byte(byte);
    }
    std::cout << std::endl;
}
```

Output:

```
{i7compactTi6schemaF}
[i1i2i3i4i5i6i7i8]
[#i8i1i2i3i4i5i6i7i8
[$i#i812345678
```

## See also

- [from_bjdata](https://json.nlohmann.me/api/basic_json/from_bjdata/index.md) create a JSON value from an input in BJData format
- [to_cbor](https://json.nlohmann.me/api/basic_json/to_cbor/index.md) create a CBOR serialization of a JSON value
- [to_msgpack](https://json.nlohmann.me/api/basic_json/to_msgpack/index.md) create a MessagePack serialization of a JSON value
- [to_bson](https://json.nlohmann.me/api/basic_json/to_bson/index.md) create a BSON serialization of a JSON value
- [to_ubjson](https://json.nlohmann.me/api/basic_json/to_ubjson/index.md) create a UBJSON serialization of a JSON value

## Version history

- Added in version 3.11.0.
- BJData version parameter (for draft3 binary encoding) added in version 3.12.0.
