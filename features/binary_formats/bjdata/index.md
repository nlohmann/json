# BJData

The [BJData format](https://neurojson.org) was derived from and improved upon [Universal Binary JSON(UBJSON)](https://ubjson.org) specification (Draft 12). Specifically, it introduces an optimized array container for efficient storage of N-dimensional packed arrays (**ND-arrays**); it also adds 5 new type markers - `[u] - uint16`, `[m] - uint32`, `[M] - uint64`, `[h] - float16` and `[B] - byte` - to unambiguously map common binary numeric types; furthermore, it uses little-endian (LE) to store all numerics instead of big-endian (BE) as in UBJSON to avoid unnecessary conversions on commonly available platforms.

Compared to other binary JSON-like formats such as MessagePack and CBOR, both BJData and UBJSON demonstrate a rare combination of being both binary and **quasi-human-readable**. This is because all semantic elements in BJData and UBJSON, including the data-type markers and name/string types, are directly human-readable. Data stored in the BJData/UBJSON format is not only compact in size, fast to read/write, but also can be directly searched or read using simple processing.

References

- [BJData Specification](https://neurojson.org/bjdata/draft2)

## Serialization

The library uses the following mapping from JSON values types to BJData types according to the BJData specification:

| JSON value type | value/range                               | BJData type | marker |
| --------------- | ----------------------------------------- | ----------- | ------ |
| null            | `null`                                    | null        | `Z`    |
| boolean         | `true`                                    | true        | `T`    |
| boolean         | `false`                                   | false       | `F`    |
| number_integer  | -9223372036854775808..-2147483649         | int64       | `L`    |
| number_integer  | -2147483648..-32769                       | int32       | `l`    |
| number_integer  | -32768..-129                              | int16       | `I`    |
| number_integer  | -128..127                                 | int8        | `i`    |
| number_integer  | 128..255                                  | uint8       | `U`    |
| number_integer  | 256..32767                                | int16       | `I`    |
| number_integer  | 32768..65535                              | uint16      | `u`    |
| number_integer  | 65536..2147483647                         | int32       | `l`    |
| number_integer  | 2147483648..4294967295                    | uint32      | `m`    |
| number_integer  | 4294967296..9223372036854775807           | int64       | `L`    |
| number_integer  | 9223372036854775808..18446744073709551615 | uint64      | `M`    |
| number_unsigned | 0..127                                    | int8        | `i`    |
| number_unsigned | 128..255                                  | uint8       | `U`    |
| number_unsigned | 256..32767                                | int16       | `I`    |
| number_unsigned | 32768..65535                              | uint16      | `u`    |
| number_unsigned | 65536..2147483647                         | int32       | `l`    |
| number_unsigned | 2147483648..4294967295                    | uint32      | `m`    |
| number_unsigned | 4294967296..9223372036854775807           | int64       | `L`    |
| number_unsigned | 9223372036854775808..18446744073709551615 | uint64      | `M`    |
| number_float    | *any value*                               | float64     | `D`    |
| string          | *with shortest length indicator*          | string      | `S`    |
| array           | *see notes on optimized format/ND-array*  | array       | `[`    |
| object          | *see notes on optimized format*           | map         | `{`    |
| binary          | *see notes on binary values*              | array       | `[$B`  |

Complete mapping

The mapping is **complete** in the sense that any JSON value type can be converted to a BJData value.

Any BJData output created by `to_bjdata` can be successfully parsed by `from_bjdata`.

Size constraints

The following values can **not** be converted to a BJData value:

- strings with more than 18446744073709551615 bytes, i.e., 2^{64}-1 bytes (theoretical)

Unused BJData markers

The following markers are not used in the conversion:

- `Z`: no-op values are not created.
- `C`: single-byte strings are serialized with `S` markers.

NaN/infinity handling

If NaN or Infinity are stored inside a JSON number, they are serialized properly. This behavior differs from the `dump()` function which serializes NaN or Infinity to `null`.

Endianness

A breaking difference between BJData and UBJSON is the endianness of numerical values. In BJData, all numerical data types (integers `UiuImlML` and floating-point values `hdD`) are stored in the little-endian (LE) byte order as opposed to big-endian as used by UBJSON. Adopting LE to store numeric records avoids unnecessary byte swapping on most modern computers where LE is used as the default byte order.

Optimized formats

Optimized formats for containers are supported via two parameters of [`to_bjdata`](https://json.nlohmann.me/api/basic_json/to_bjdata/index.md):

- Parameter `use_size` adds size information to the beginning of a container and removes the closing marker.
- Parameter `use_type` further checks whether all elements of a container have the same type and adds the type marker to the beginning of the container. The `use_type` parameter must only be used together with `use_size = true`.

Note that `use_size = true` alone may result in larger representations - the benefit of this parameter is that the receiving side is immediately informed of the number of elements in the container.

ND-array optimized format

BJData extends UBJSON's optimized array **size** marker to support ND-arrays of uniform numerical data types (referred to as *packed arrays*). For example, the 2-D `uint8` integer array `[[1,2],[3,4],[5,6]]`, stored as nested optimized array in UBJSON `[ [$U#i2 1 2 [$U#i2 3 4 [$U#i2 5 6 ]`, can be further compressed in BJData to `[$U#[$i#i2 2 3 1 2 3 4 5 6` or `[$U#[i2 i3] 1 2 3 4 5 6`.

To maintain type and size information, ND-arrays are converted to JSON objects following the **annotated array format** (defined in the [JData specification (Draft 3)](https://github.com/NeuroJSON/jdata/blob/master/JData_specification.md#annotated-storage-of-n-d-arrays)), when parsed using [`from_bjdata`](https://json.nlohmann.me/api/basic_json/from_bjdata/index.md). For example, the above 2-D `uint8` array can be parsed and accessed as

```
{
    "_ArrayType_": "uint8",
    "_ArraySize_": [2,3],
    "_ArrayData_": [1,2,3,4,5,6]
}
```

Likewise, when a JSON object in the above form is serialized using [`to_bjdata`](https://json.nlohmann.me/api/basic_json/to_bjdata/index.md), it is automatically converted into a compact BJData ND-array. When the 1-dimensional vector stored in `"_ArraySize_"` contains a single integer or two integers with one being 1, a regular 1-D optimized array is generated instead.

An object is only converted if the annotation actually describes a packed array; otherwise it is serialized as a regular JSON object. This requires all of the following:

- `"_ArrayType_"` is one of `uint8`, `int8`, `uint16`, `int16`, `uint32`, `int32`, `uint64`, `int64`, `single`, `double`, `char`, or `byte`,
- every entry of `"_ArraySize_"` is a non-negative integer, and their product is representable as a `std::size_t`,
- `"_ArrayData_"` holds exactly that many elements, and
- every element of `"_ArrayData_"` is a number of the kind named by `"_ArrayType_"` (a floating-point number for `single` and `double`, an integer otherwise).

The current version of this library does not yet support automatic detection of and conversion from a nested JSON array input to a BJData ND-array.

Restrictions in optimized data types for arrays and objects

Due to diminished space saving, hampered readability, and increased security risks, in BJData, the allowed data types following the `$` marker in an optimized array and object container are restricted to **non-zero-fixed-length** data types. Therefore, the valid optimized type markers can only be one of `UiuImlMLhdDCB`. This also means other variable (`[{SH`) or zero-length types (`TFN`) can not be used in an optimized array or object in BJData.

Binary values

BJData provides a dedicated `B` marker (defined in the [BJData specification (Draft 3)](https://github.com/NeuroJSON/bjdata/blob/master/Binary_JData_Specification.md#optimized-binary-array)) that is used in optimized arrays to designate binary data. This means that, unlike UBJSON, binary data can be both serialized and deserialized.

To preserve compatibility with BJData Draft 2, the Draft 3 optimized binary array must be explicitly enabled using the `version` parameter of [`to_bjdata`](https://json.nlohmann.me/api/basic_json/to_bjdata/index.md).

In Draft2 mode (default), if the JSON data contains the binary type, the value stored as a list of integers, as suggested by the BJData documentation. In particular, this means that the serialization and the deserialization of JSON containing binary values into BJData and back will result in a different JSON object.

Example

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

## Deserialization

The library maps BJData types to JSON value types as follows:

| BJData type | JSON value type                          | marker   |
| ----------- | ---------------------------------------- | -------- |
| no-op       | *no value, next value is read*           | `N`      |
| null        | `null`                                   | `Z`      |
| false       | `false`                                  | `F`      |
| true        | `true`                                   | `T`      |
| float16     | number_float                             | `h`      |
| float32     | number_float                             | `d`      |
| float64     | number_float                             | `D`      |
| uint8       | number_unsigned                          | `U`      |
| int8        | number_integer                           | `i`      |
| uint16      | number_unsigned                          | `u`      |
| int16       | number_integer                           | `I`      |
| uint32      | number_unsigned                          | `m`      |
| int32       | number_integer                           | `l`      |
| uint64      | number_unsigned                          | `M`      |
| int64       | number_integer                           | `L`      |
| byte        | number_unsigned                          | `B`      |
| string      | string                                   | `S`      |
| char        | string                                   | `C`      |
| array       | array (optimized values are supported)   | `[`      |
| ND-array    | object (in JData annotated array format) | `[$.#[.` |
| object      | object (optimized values are supported)  | `{`      |
| binary      | binary (strongly-typed byte array)       | `[$B`    |

Complete mapping

The mapping is **complete** in the sense that any BJData value can be converted to a JSON value.

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

    // deserialize it with BJData
    json j = json::from_bjdata(v);

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
