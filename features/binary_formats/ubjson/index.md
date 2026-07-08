# UBJSON

Universal Binary JSON (UBJSON) is a binary form directly imitating JSON, but requiring fewer bytes of data. It aims to achieve the generality of JSON, combined with being much easier to process than JSON.

References

- [UBJSON Website](http://ubjson.org)

## Serialization

The library uses the following mapping from JSON values types to UBJSON types according to the UBJSON specification:

| JSON value type | value/range                       | UBJSON type    | marker |
| --------------- | --------------------------------- | -------------- | ------ |
| null            | `null`                            | null           | `Z`    |
| boolean         | `true`                            | true           | `T`    |
| boolean         | `false`                           | false          | `F`    |
| number_integer  | -9223372036854775808..-2147483649 | int64          | `L`    |
| number_integer  | -2147483648..-32769               | int32          | `l`    |
| number_integer  | -32768..-129                      | int16          | `I`    |
| number_integer  | -128..127                         | int8           | `i`    |
| number_integer  | 128..255                          | uint8          | `U`    |
| number_integer  | 256..32767                        | int16          | `I`    |
| number_integer  | 32768..2147483647                 | int32          | `l`    |
| number_integer  | 2147483648..9223372036854775807   | int64          | `L`    |
| number_unsigned | 0..127                            | int8           | `i`    |
| number_unsigned | 128..255                          | uint8          | `U`    |
| number_unsigned | 256..32767                        | int16          | `I`    |
| number_unsigned | 32768..2147483647                 | int32          | `l`    |
| number_unsigned | 2147483648..9223372036854775807   | int64          | `L`    |
| number_unsigned | 2147483649..18446744073709551615  | high-precision | `H`    |
| number_float    | *any value*                       | float64        | `D`    |
| string          | *with shortest length indicator*  | string         | `S`    |
| array           | *see notes on optimized format*   | array          | `[`    |
| object          | *see notes on optimized format*   | map            | `{`    |

Complete mapping

The mapping is **complete** in the sense that any JSON value type can be converted to a UBJSON value.

Any UBJSON output created by `to_ubjson` can be successfully parsed by `from_ubjson`.

Size constraints

The following values can **not** be converted to a UBJSON value:

- strings with more than 9223372036854775807 bytes (theoretical)

Unused UBJSON markers

The following markers are not used in the conversion:

- `Z`: no-op values are not created.
- `C`: single-byte strings are serialized with `S` markers.

NaN/infinity handling

If NaN or Infinity are stored inside a JSON number, they are serialized properly. This behavior differs from the `dump()` function which serializes NaN or Infinity to `null`.

Optimized formats

The optimized formats for containers are supported: Parameter `use_size` adds size information to the beginning of a container and removes the closing marker. Parameter `use_type` further checks whether all elements of a container have the same type and adds the type marker to the beginning of the container. The `use_type` parameter must only be used together with `use_size = true`.

Note that `use_size = true` alone may result in larger representations - the benefit of this parameter is that the receiving side is immediately informed on the number of elements of the container.

Binary values

If the JSON data contains the binary type, the value stored is a list of integers, as suggested by the UBJSON documentation. In particular, this means that serialization and the deserialization of a JSON containing binary values into UBJSON and back will result in a different JSON object.

Example

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace nlohmann::literals;

// function to print UBJSON's diagnostic format
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

    // serialize it to UBJSON
    std::vector<std::uint8_t> v = json::to_ubjson(j);

    // print the vector content
    for (auto& byte : v)
    {
        print_byte(byte);
    }
    std::cout << std::endl;

    // create an array of numbers
    json array = {1, 2, 3, 4, 5, 6, 7, 8};

    // serialize it to UBJSON using default representation
    std::vector<std::uint8_t> v_array = json::to_ubjson(array);
    // serialize it to UBJSON using size optimization
    std::vector<std::uint8_t> v_array_size = json::to_ubjson(array, true);
    // serialize it to UBJSON using type optimization
    std::vector<std::uint8_t> v_array_size_and_type = json::to_ubjson(array, true, true);

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

## Deserialization

The library maps UBJSON types to JSON value types as follows:

| UBJSON type | JSON value type                         | marker |
| ----------- | --------------------------------------- | ------ |
| no-op       | *no value, next value is read*          | `N`    |
| null        | `null`                                  | `Z`    |
| false       | `false`                                 | `F`    |
| true        | `true`                                  | `T`    |
| float32     | number_float                            | `d`    |
| float64     | number_float                            | `D`    |
| uint8       | number_unsigned                         | `U`    |
| int8        | number_integer                          | `i`    |
| int16       | number_integer                          | `I`    |
| int32       | number_integer                          | `l`    |
| int64       | number_integer                          | `L`    |
| string      | string                                  | `S`    |
| char        | string                                  | `C`    |
| array       | array (optimized values are supported)  | `[`    |
| object      | object (optimized values are supported) | `{`    |

Complete mapping

The mapping is **complete** in the sense that any UBJSON value can be converted to a JSON value.

Example

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create byte vector
    std::vector<std::uint8_t> v = {0x7B, 0x69, 0x07, 0x63, 0x6F, 0x6D, 0x70, 0x61,
                                   0x63, 0x74, 0x54, 0x69, 0x06, 0x73, 0x63, 0x68,
                                   0x65, 0x6D, 0x61, 0x69, 0x00, 0x7D
                                  };

    // deserialize it with UBJSON
    json j = json::from_ubjson(v);

    // print the deserialized JSON value
    std::cout << std::setw(2) << j << std::endl;
}
```

Output:

```
{
  "compact": true,
  "schema": 0
}
```
