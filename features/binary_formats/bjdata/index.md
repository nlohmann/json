# BJData

The [BJData format](https://neurojson.org) was derived from and improved upon [Universal Binary JSON(UBJSON)](https://ubjson.org) specification (Draft 12). Specifically, it introduces an optimized array container for efficient storage of N-dimensional packed arrays (**ND-arrays**); it also adds four new type markers - `[u] - uint16`, `[m] - uint32`, `[M] - uint64`, and `[h] - float16` - to unambiguously map common binary numeric types (Draft 3 adds `[B] - byte`); furthermore, it uses little-endian (LE) to store all numerics instead of big-endian (BE) as in UBJSON to avoid unnecessary conversions on commonly available platforms.

Compared to other binary JSON-like formats such as MessagePack and CBOR, both BJData and UBJSON demonstrate a rare combination of being both binary and **quasi-human-readable**. This is because all semantic elements in BJData and UBJSON, including the data-type markers and name/string types, are directly human-readable. Data stored in the BJData/UBJSON format is not only compact in size, fast to read/write, but also can be directly searched or read using simple processing.

References

- [BJData Specification (Draft 3)](https://neurojson.org/bjdata/draft3)
- [BJData Specification (Draft 2)](https://neurojson.org/bjdata/draft2)

Supported drafts

The library supports BJData Draft 2 (the default) and Draft 3, except for column-major N-dimensional arrays (see below). The draft used for writing is selected with the [`version` parameter](https://json.nlohmann.me/api/basic_json/bjdata_version_t/index.md) of [`to_bjdata`](https://json.nlohmann.me/api/basic_json/to_bjdata/index.md); [`from_bjdata`](https://json.nlohmann.me/api/basic_json/from_bjdata/index.md) has no such parameter and reads the markers of both drafts.

Draft 4 and column-major ND-arrays are not supported

BJData Draft 4 (April 2026) adds structure-of-arrays (SoA) containers (`[$` or `{$` followed by a schema object) and the extension type `E`. `from_bjdata` does not implement them and throws [`parse_error.112`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error112) for such input; `to_bjdata` never writes them.

Likewise, column-major ND-arrays of Draft 3 (the `#` marker followed by an array that wraps the dimension vector) are rejected with [`parse_error.113`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error113).

## Byte layout

BJData follows the structure of UBJSON: a one-byte, human-readable ASCII *type marker* followed by the payload of that type, with strings prefixed by a length that is itself an integer value. In contrast to UBJSON, numbers are stored in little-endian byte order, and additional markers cover unsigned 16/32/64-bit integers, half-precision floats, and bytes. Containers can be written unoptimized (opened with `[` or `{`, closed with `]` or `}`) or optimized with a count (`#`), optionally preceded by a declared element type (`$`). BJData extends the optimized form: the count can be a list of dimensions, which stores an N-dimensional packed array as a flat sequence of values without any per-element markers.

Consider the following JSON value (shown formatted for readability):

```
{
  "id": 300,
  "name": "json",
  "pi": 3.14,
  "tags": [
    "a",
    "b"
  ]
}
```

`to_bjdata` encodes it to 51 bytes (shown in hexadecimal; the encoding contains no whitespace). The colors mark the role of each byte: type/marker length/count/size data.

| JSON              | Bytes                                  | Meaning                                                                          |
| ----------------- | -------------------------------------- | -------------------------------------------------------------------------------- |
| `{`               | 7B                                     | object start (`{`)                                                               |
| `"id": 300,`      | 69 02 69 64 49 2C 01                   | key: length 2 as int8 (`i`), then UTF-8 bytes; value: int16 (`I`), little-endian |
| `"name": "json",` | 69 04 6E 61 6D 65 53 69 04 6A 73 6F 6E | key: length 4; value: string (`S`), length 4 as int8, UTF-8 bytes                |
| `"pi": 3.14,`     | 69 02 70 69 44 1F 85 EB 51 B8 1E 09 40 | key: length 2; value: float64 (`D`), little-endian                               |
| `"tags": [`       | 69 04 74 61 67 73 5B                   | key: length 4; value: array start (`[`)                                          |
| `"a",`            | 53 69 01 61                            | string, length 1                                                                 |
| `"b"`             | 53 69 01 62                            | string, length 1                                                                 |
| `]`               | 5D                                     | array end (`]`)                                                                  |
| `}`               | 7D                                     | object end (`}`)                                                                 |

## Serialization

The library uses the following mapping from JSON values types to BJData types according to the BJData specification:

| JSON value type | value/range                               | BJData type | marker                                                                  |
| --------------- | ----------------------------------------- | ----------- | ----------------------------------------------------------------------- |
| null            | `null`                                    | null        | `Z`                                                                     |
| boolean         | `true`                                    | true        | `T`                                                                     |
| boolean         | `false`                                   | false       | `F`                                                                     |
| number_integer  | -9223372036854775808..-2147483649         | int64       | `L`                                                                     |
| number_integer  | -2147483648..-32769                       | int32       | `l`                                                                     |
| number_integer  | -32768..-129                              | int16       | `I`                                                                     |
| number_integer  | -128..127                                 | int8        | `i`                                                                     |
| number_integer  | 128..255                                  | uint8       | `U`                                                                     |
| number_integer  | 256..32767                                | int16       | `I`                                                                     |
| number_integer  | 32768..65535                              | uint16      | `u`                                                                     |
| number_integer  | 65536..2147483647                         | int32       | `l`                                                                     |
| number_integer  | 2147483648..4294967295                    | uint32      | `m`                                                                     |
| number_integer  | 4294967296..9223372036854775807           | int64       | `L`                                                                     |
| number_integer  | 9223372036854775808..18446744073709551615 | uint64      | `M`                                                                     |
| number_unsigned | 0..127                                    | int8        | `i`                                                                     |
| number_unsigned | 128..255                                  | uint8       | `U`                                                                     |
| number_unsigned | 256..32767                                | int16       | `I`                                                                     |
| number_unsigned | 32768..65535                              | uint16      | `u`                                                                     |
| number_unsigned | 65536..2147483647                         | int32       | `l`                                                                     |
| number_unsigned | 2147483648..4294967295                    | uint32      | `m`                                                                     |
| number_unsigned | 4294967296..9223372036854775807           | int64       | `L`                                                                     |
| number_unsigned | 9223372036854775808..18446744073709551615 | uint64      | `M`                                                                     |
| number_float    | *any value*                               | float64     | `D`                                                                     |
| string          | *with shortest length indicator*          | string      | `S`                                                                     |
| array           | *see notes on optimized format/ND-array*  | array       | `[`                                                                     |
| object          | *see notes on optimized format*           | map         | `{`                                                                     |
| binary          | *see notes on binary values*              | array       | `[$B` (Draft 3 with `use_size` and `use_type`), `[U`, or `[B` otherwise |

Complete mapping

The mapping is **complete** in the sense that any JSON value type can be converted to a BJData value.

Any BJData output created by `to_bjdata` can be successfully parsed by `from_bjdata`.

Size constraints

The following values can **not** be converted to a BJData value:

- strings with more than 18446744073709551615 bytes, i.e., 264-1 bytes (theoretical)

UTF-8 validation of string values and object keys

BJData strings must use UTF-8 encoding. By default (the [`error_handler`](https://json.nlohmann.me/api/basic_json/to_bjdata/index.md) parameter left at `keep`), `to_bjdata()` writes the bytes of string values and object keys unchanged, even if they are not valid UTF-8. With `error_handler_t::strict`, it throws [`type_error.316`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error316) for ill-formed UTF-8 instead; `replace`/`ignore` sanitize the string. [`JSON_STRICT_BINARY_UTF8`](https://json.nlohmann.me/api/macros/json_strict_binary_utf8/index.md) makes `strict` the default.

Unused BJData markers

The following markers are not written:

- `N`: no-op values are not created (they are skipped when reading).
- `C`: single-character strings are serialized with `S` markers (`C` is read, and written for the elements of ND-arrays with `"_ArrayType_": "char"`).
- `h`: floating-point numbers are written as `D`, not as float16 (`h` is read).
- `B`: only written in Draft 3 mode.
- `d` is only written for `single` ND-arrays or if `number_float_t` is `float`; `H` is only written for integers wider than 64 bits (custom `number_integer_t`/`number_unsigned_t`). An unsigned integer above 9223372036854775807 is written as `M`.

NaN/infinity handling

If NaN or Infinity are stored inside a JSON number, they are serialized properly. This behavior differs from the [`dump()`](https://json.nlohmann.me/api/basic_json/dump/index.md) function which serializes NaN or Infinity to `null`.

Endianness

A breaking difference between BJData and UBJSON is the endianness of numerical values. In BJData, all numerical data types (integers `UiuImlML` and floating-point values `hdD`) are stored in the little-endian (LE) byte order as opposed to big-endian as used by UBJSON. Adopting LE to store numeric records avoids unnecessary byte swapping on most modern computers where LE is used as the default byte order.

Optimized formats

Optimized formats for containers are supported via two parameters of [`to_bjdata`](https://json.nlohmann.me/api/basic_json/to_bjdata/index.md):

- Parameter `use_size` adds size information to the beginning of a container and removes the closing marker.
- Parameter `use_type` further checks whether all elements of a container have the same type and adds the type marker to the beginning of the container. The `use_type` parameter must only be used together with `use_size = true`.

Note that `use_size = true` alone may result in larger representations - the benefit of this parameter is that the receiving side is immediately informed of the number of elements in the container.

ND-array optimized format

BJData extends UBJSON's optimized array **size** marker to support ND-arrays of uniform numerical data types (referred to as *packed arrays*). For example, the 2-D `uint8` integer array `[[1,2],[3,4],[5,6]]`, stored as nested optimized array in UBJSON `[ [$U#i2 1 2 [$U#i2 3 4 [$U#i2 5 6 ]`, can be further compressed in BJData to `[$U#[$i#i2 3 2 1 2 3 4 5 6` or `[$U#[i3 i2] 1 2 3 4 5 6`.

To maintain type and size information, ND-arrays are converted to JSON objects following the **annotated array format** (defined in the [JData specification (Draft 3)](https://github.com/NeuroJSON/jdata/blob/Draft-3/JData_specification.md#annotated-storage-of-n-d-arrays)), when parsed using [`from_bjdata`](https://json.nlohmann.me/api/basic_json/from_bjdata/index.md). For example, the above 2-D `uint8` array can be parsed and accessed as

```
{
    "_ArrayType_": "uint8",
    "_ArraySize_": [3,2],
    "_ArrayData_": [1,2,3,4,5,6]
}
```

ND-arrays with the element type `h` (float16) are returned with `"_ArrayType_": "half"`. `to_bjdata` does not pack `"half"` objects; they are written as regular objects, which read back as an equal value.

Likewise, when a JSON object in the above form is serialized using [`to_bjdata`](https://json.nlohmann.me/api/basic_json/to_bjdata/index.md), it is automatically converted into a compact BJData ND-array.

When parsing, an ND-array whose dimension vector is empty, contains a single integer, contains two integers with the first being 1, or contains a 0 is returned as a regular (possibly empty) array rather than an annotated object.

An object is only converted if the annotation describes a packed array that is parsed back into the same annotated object; otherwise it is serialized as a regular JSON object, so the annotation is never lost in a round trip. This requires all of the following:

- the object has exactly the three keys `"_ArrayType_"`, `"_ArraySize_"`, and `"_ArrayData_"` (any other key, e.g., `"_ArrayOrder_"`, makes it a regular object),
- `"_ArrayType_"` is one of `uint8`, `int8`, `uint16`, `int16`, `uint32`, `int32`, `uint64`, `int64`, `single`, `double`, `char`, or (only with `version = bjdata_version_t::draft3`, since the `B` marker is not part of Draft 2) `byte`; the names are case-sensitive,
- `"_ArraySize_"` is an array, since the dimensions are written as the ND-array header's length,
- `"_ArraySize_"` has at least two entries and is not a two-entry row vector (`[1,N]`), since other shapes are parsed back as a regular array (`[1,2,2]` is packed, `[1,4]` is not),
- every entry of `"_ArraySize_"` is a positive integer, and their product is representable as a `std::size_t`,
- `"_ArrayData_"` is an array holding exactly that many elements, and
- every element of `"_ArrayData_"` is a number of the kind named by `"_ArrayType_"`: for the integer types, an integer (a floating-point number such as `1.0` does not qualify) that fits the named width (for `char`, 0..127); for `double`, a floating-point number (an integer such as `1` does not qualify); for `single`, a floating-point number that survives narrowing to `float` and back without change (for instance, `0.1` does not, since it is not exactly representable as `float`).

With `ordered_json`, an annotated object read from BJData has its keys in the order `"_ArrayType_"`, `"_ArraySize_"`, `"_ArrayData_"`; with `json`, they are sorted like those of any other object.

The current version of this library does not yet support automatic detection of and conversion from a nested JSON array input to a BJData ND-array.

Restrictions in optimized data types for arrays and objects

Due to diminished space saving, hampered readability, and increased security risks, in BJData, the allowed data types following the `$` marker in an optimized array and object container are restricted to **non-zero-fixed-length** data types. Therefore, the valid optimized type markers can only be one of `UiuImlMLhdDC`, plus `B` since Draft 3 (the reader accepts `B` in both drafts). This also means other variable (`[{SH`) or zero-length types (`TFZN`) can not be used in an optimized array or object in BJData. The library enforces this restriction for both drafts. A `C` (char) element above 127 is rejected on read with [`parse_error.113`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error113), in 1-D and in N-dimensional arrays. With `use_type`, the elements must have the same marker (`[1,200,3]` is not optimized, since it mixes `i` and `U`); booleans, null, strings, arrays, and objects are never optimized with `$`.

Binary values

BJData provides a dedicated `B` marker (defined in the [BJData specification (Draft 3)](https://github.com/NeuroJSON/bjdata/blob/Draft-3/Binary_JData_Specification.md#optimized-binary-array)) that is used in optimized arrays to designate binary data. This means that, unlike UBJSON, binary data can be both serialized and deserialized.

To preserve compatibility with BJData Draft 2, the Draft 3 optimized binary array must be explicitly enabled: pass `version = bjdata_version_t::draft3` together with `use_size = true` and `use_type = true` to [`to_bjdata`](https://json.nlohmann.me/api/basic_json/to_bjdata/index.md). With Draft 3 and only `use_size` (or neither), a binary value is written as an array of `B` elements.

In Draft 2 mode (default), if the JSON data contains the binary type, the value is stored as a list of integers, as suggested by the BJData documentation. In particular, this means that the serialization and the deserialization of JSON containing binary values into BJData and back will result in a different JSON object.

Example: serialize JSON values to BJData, with and without size/type optimization

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using nlohmann::json;
using namespace nlohmann::literals;

// function to print BJData's diagnostic format
void print_byte(uint8_t byte)
{
    if (32 < byte and byte < 128)
    {
        std::cout << static_cast<char>(byte);
    }
    else
    {
        std::cout << static_cast<int>(byte);
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
    std::cout << '\n';

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
    std::cout << '\n';

    for (auto& byte : v_array_size)
    {
        print_byte(byte);
    }
    std::cout << '\n';

    for (auto& byte : v_array_size_and_type)
    {
        print_byte(byte);
    }
    std::cout << '\n';
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

| BJData type           | JSON value type                                  | marker   |
| --------------------- | ------------------------------------------------ | -------- |
| no-op                 | *no value, next value is read*                   | `N`      |
| null                  | `null`                                           | `Z`      |
| false                 | `false`                                          | `F`      |
| true                  | `true`                                           | `T`      |
| float16               | number_float                                     | `h`      |
| float32               | number_float                                     | `d`      |
| float64               | number_float                                     | `D`      |
| high-precision number | number_integer, number_unsigned, or number_float | `H`      |
| uint8                 | number_unsigned                                  | `U`      |
| int8                  | number_integer                                   | `i`      |
| uint16                | number_unsigned                                  | `u`      |
| int16                 | number_integer                                   | `I`      |
| uint32                | number_unsigned                                  | `m`      |
| int32                 | number_integer                                   | `l`      |
| uint64                | number_unsigned                                  | `M`      |
| int64                 | number_integer                                   | `L`      |
| byte                  | number_unsigned                                  | `B`      |
| string                | string                                           | `S`      |
| char                  | string                                           | `C`      |
| array                 | array (optimized values are supported)           | `[`      |
| ND-array              | object (in JData annotated array format)         | `[$.#[.` |
| object                | object (optimized values are supported)          | `{`      |
| binary                | binary (strongly-typed byte array)               | `[$B`    |

Complete mapping

The mapping is **complete** for the BJData types of Draft 2 and Draft 3 with one exception: column-major N-dimensional arrays are rejected with [`parse_error.113`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error113). The Draft 4 constructs (structure-of-arrays containers and the extension type `E`) are not supported either.

The digits of an `H` value are parsed like a JSON number: integers that fit 64 bits become `number_integer` or `number_unsigned`, anything else a `number_float`; invalid text throws [`parse_error.115`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error115).

Duplicate object keys

If an object contains the same key more than once, `from_bjdata` accepts it and keeps the last value; with `ordered_json`, the key keeps the position of its first occurrence.

Ill-formed UTF-8 in string values and object keys

BJData strings must use UTF-8 encoding, but checking it on read is opt-in: with the [`error_handler`](https://json.nlohmann.me/api/basic_json/from_bjdata/index.md) parameter left at `keep` (the default), `from_bjdata()` accepts a string value or object key whose bytes are not valid UTF-8 and hands them back unchanged. Passing `error_handler_t::strict` makes `from_bjdata()` check and throw [`parse_error.113`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error113) for ill-formed UTF-8, and `replace`/`ignore` sanitize the string instead of keeping it. However, [`dump()`](https://json.nlohmann.me/api/basic_json/dump/index.md) still requires valid UTF-8 and throws [`type_error.316`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error316) for a value read with the default `keep` handler, unless an error handler is passed that replaces or ignores the ill-formed bytes. `to_bjdata()`'s own `error_handler` parameter defaults to `keep` (see above), so such a value is written back unchanged.

Round trips

A value returned by [`from_bjdata`](https://json.nlohmann.me/api/basic_json/from_bjdata/index.md) can be serialized with [`to_bjdata`](https://json.nlohmann.me/api/basic_json/to_bjdata/index.md) using any combination of options and parsed back into an equal value, and serializing that value again with the same options produces the same bytes. The exception is binary values: they are only written as an optimized binary array (`[$B`) if Draft 3 is enabled and both `use_size` and `use_type` are set. Otherwise, they are written as arrays of integers and parsed back as such (see the notes on binary values above), and serializing such an array again may choose different, but equally valid, type markers. The bytes can then differ, but parsing them again yields the same value.

Example: deserialize a JSON value from BJData

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using nlohmann::json;

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
    std::cout << std::setw(2) << j << '\n';
}
```

Output:

```
{
  "compact": true,
  "schema": 0
}
```
