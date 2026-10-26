# UBJSON

Universal Binary JSON (UBJSON) is a binary form directly imitating JSON, but requiring fewer bytes of data. It aims to achieve the generality of JSON, combined with being much easier to process than JSON.

References

- [UBJSON Website](https://ubjson.org)

## Byte layout

UBJSON is built from just a one-byte, human-readable ASCII *type marker* (for example, `i` for int8, `S` for string, `[` for array) followed by the payload of that type. Strings and the like are prefixed with their length, which is itself a UBJSON integer value including its marker. Numbers are stored in big-endian byte order. Containers can be written in two ways: as an *unoptimized* container that is opened with `[` or `{` and closed with `]` or `}`, or as an *optimized* container that declares a count (`#`) after the opening marker, optionally preceded by an element type (`$`); an element type is only allowed together with a count. An optimized container saves the closing marker and, with a type, the per-element markers.

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

`to_ubjson` encodes it to 51 bytes (shown in hexadecimal; the encoding contains no whitespace). The colors mark the role of each byte: type/marker length/count/size data.

| JSON              | Bytes                                  | Meaning                                                                       |
| ----------------- | -------------------------------------- | ----------------------------------------------------------------------------- |
| `{`               | 7B                                     | object start (`{`)                                                            |
| `"id": 300,`      | 69 02 69 64 49 01 2C                   | key: length 2 as int8 (`i`), then UTF-8 bytes; value: int16 (`I`), big-endian |
| `"name": "json",` | 69 04 6E 61 6D 65 53 69 04 6A 73 6F 6E | key: length 4; value: string (`S`), length 4 as int8, UTF-8 bytes             |
| `"pi": 3.14,`     | 69 02 70 69 44 40 09 1E B8 51 EB 85 1F | key: length 2; value: float64 (`D`), big-endian                               |
| `"tags": [`       | 69 04 74 61 67 73 5B                   | key: length 4; value: array start (`[`)                                       |
| `"a",`            | 53 69 01 61                            | string, length 1                                                              |
| `"b"`             | 53 69 01 62                            | string, length 1                                                              |
| `]`               | 5D                                     | array end (`]`)                                                               |
| `}`               | 7D                                     | object end (`}`)                                                              |

## Serialization

The library uses the following mapping from JSON values types to UBJSON types according to the UBJSON specification:

| JSON value type | value/range                               | UBJSON type                                      | marker    |
| --------------- | ----------------------------------------- | ------------------------------------------------ | --------- |
| null            | `null`                                    | null                                             | `Z`       |
| boolean         | `true`                                    | true                                             | `T`       |
| boolean         | `false`                                   | false                                            | `F`       |
| number_integer  | -9223372036854775808..-2147483649         | int64                                            | `L`       |
| number_integer  | -2147483648..-32769                       | int32                                            | `l`       |
| number_integer  | -32768..-129                              | int16                                            | `I`       |
| number_integer  | -128..127                                 | int8                                             | `i`       |
| number_integer  | 128..255                                  | uint8                                            | `U`       |
| number_integer  | 256..32767                                | int16                                            | `I`       |
| number_integer  | 32768..2147483647                         | int32                                            | `l`       |
| number_integer  | 2147483648..9223372036854775807           | int64                                            | `L`       |
| number_unsigned | 0..127                                    | int8                                             | `i`       |
| number_unsigned | 128..255                                  | uint8                                            | `U`       |
| number_unsigned | 256..32767                                | int16                                            | `I`       |
| number_unsigned | 32768..2147483647                         | int32                                            | `l`       |
| number_unsigned | 2147483648..9223372036854775807           | int64                                            | `L`       |
| number_unsigned | 9223372036854775808..18446744073709551615 | high-precision                                   | `H`       |
| number_float    | *any value*                               | float64 (float32 if `number_float_t` is `float`) | `D` (`d`) |
| string          | *with shortest length indicator*          | string                                           | `S`       |
| array           | *see notes on optimized format*           | array                                            | `[`       |
| object          | *see notes on optimized format*           | object                                           | `{`       |

Complete mapping

The mapping is **complete** in the sense that any JSON value type can be converted to a UBJSON value.

Any UBJSON output created by `to_ubjson` can be successfully parsed by `from_ubjson`.

Size constraints

The following values can **not** be converted to a UBJSON value:

- strings with more than 9223372036854775807 bytes (theoretical)

UTF-8 validation of string values and object keys

UBJSON's required string encoding is UTF-8. By default (the [`error_handler`](https://json.nlohmann.me/api/basic_json/to_ubjson/index.md) parameter left at `keep`), `to_ubjson()` writes the bytes of string values and object keys unchanged, even if they are not valid UTF-8. With `error_handler_t::strict`, it throws [`type_error.316`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error316) for ill-formed UTF-8 instead; `replace`/`ignore` sanitize the string. [`JSON_STRICT_BINARY_UTF8`](https://json.nlohmann.me/api/macros/json_strict_binary_utf8/index.md) makes `strict` the default.

Unused UBJSON markers

The following markers are not used in the conversion:

- `N`: no-op values are never written (they are skipped when reading).
- `C`: single-byte strings are serialized with `S` markers.

NaN/infinity handling

NaN and infinity are written as IEEE 754 float64 values (`D`) and read back unchanged. This differs from [`dump()`](https://json.nlohmann.me/api/basic_json/dump/index.md), which serializes them to `null`, and from the UBJSON specification, which encodes infinity as `null` (it does not mention NaN); other UBJSON readers may therefore not accept these values.

Optimized formats

The optimized formats for containers are supported: Parameter `use_size` adds size information to the beginning of a container and removes the closing marker. Parameter `use_type` further checks whether all elements of a container have the same type and adds the type marker to the beginning of the container. The `use_type` parameter must only be used together with `use_size = true`: combining `use_type` with `use_size = false` throws [`other_error.502`](https://json.nlohmann.me/home/exceptions/#jsonexceptionother_error502) if the value contains a non-empty array, object, or binary value.

Two elements have the same type if they are written with the same type marker. For example, `[1, 2]` is written with the type `i`, but `[1, 200]` (`i`, `U`), `[true, false]` (`T`, `F`), and `[1, 2.5]` (`i`, `D`) are not; an empty container is never given a `$` annotation of its own (an array of empty arrays is still typed `[`).

Note that `use_size = true` alone may result in larger representations - the benefit of this parameter is that the receiving side is immediately informed on the number of elements of the container.

An array whose type marker is `Z` (null), `T` (true) or `F` (false) stores no payload at all, because the marker already is the value. Its declared count is therefore the only thing that decides how much memory the receiving side allocates, and a handful of bytes can describe billions of elements. `from_ubjson` rejects such an array with [`out_of_range.408`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range408) when the count exceeds 1,048,576 (`1 << 20`), and `to_ubjson` writes longer arrays of these types in the counted but untyped form: the `$` type marker is dropped, the `#` count is kept, and every element is written with its own marker (`[#l 1048577 Z Z ...`), so any value it produces can be read back. Objects and untyped counted arrays are not subject to this limit.

Binary values

If the JSON data contains the binary type, the value stored is a list of integers, as suggested by the UBJSON documentation. In particular, this means that serialization and the deserialization of a JSON containing binary values into UBJSON and back will result in a different JSON object.

Example: serialize JSON values to UBJSON, with and without size/type optimization

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using nlohmann::json;
using namespace nlohmann::literals;

// function to print UBJSON's diagnostic format
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

    // serialize it to UBJSON
    std::vector<std::uint8_t> v = json::to_ubjson(j);

    // print the vector content
    for (auto& byte : v)
    {
        print_byte(byte);
    }
    std::cout << '\n';

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

The library maps UBJSON types to JSON value types as follows:

| UBJSON type    | JSON value type                                  | marker |
| -------------- | ------------------------------------------------ | ------ |
| no-op          | *no value, next value is read*                   | `N`    |
| null           | `null`                                           | `Z`    |
| false          | `false`                                          | `F`    |
| true           | `true`                                           | `T`    |
| float32        | number_float                                     | `d`    |
| float64        | number_float                                     | `D`    |
| uint8          | number_unsigned                                  | `U`    |
| int8           | number_integer                                   | `i`    |
| int16          | number_integer                                   | `I`    |
| int32          | number_integer                                   | `l`    |
| int64          | number_integer                                   | `L`    |
| string         | string                                           | `S`    |
| char           | string                                           | `C`    |
| high-precision | number_unsigned, number_integer, or number_float | `H`    |
| array          | array (optimized values are supported)           | `[`    |
| object         | object (optimized values are supported)          | `{`    |

High-precision numbers

The payload of `H` is a length-prefixed string that is parsed as a JSON number (surrounding whitespace is ignored). Integer text in the range of `number_unsigned_t` (non-negative) or `number_integer_t` (negative) is stored as such; any other valid number text (larger or smaller integers, fractions, and exponents such as `1e2`) is stored as `number_float`, so precision may be lost. Text that is not a valid JSON number raises [`parse_error.115`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error115), a number outside the range of `number_float_t` (`1e999`) raises [`out_of_range.406`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range406).

Complete mapping

Every well-formed UBJSON value can be converted to a JSON value, with these exceptions: a high-precision number outside the range of `number_float_t` ([`out_of_range.406`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range406)), an optimized array of `Z`, `T`, or `F` with more than 1,048,576 elements, and a count that exceeds the capacity of the container ([`out_of_range.408`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range408)). High-precision numbers that do not fit an integer type are stored as floating-point numbers and may lose precision. Ill-formed input is rejected with a parse error.

Duplicate object keys

If an object contains the same key more than once, the last value is kept (the UBJSON specification does not address duplicate keys).

Type marker of optimized containers

The type marker after `$` must be one of `Z`, `N`, `T`, `F`, `i`, `U`, `I`, `l`, `L`, `d`, `D`, `H`, `C`, `S`, `[`, or `{`. It is checked even if the count is 0; any other marker raises [`parse_error.112`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error112). A counted object typed `N` (`{$N#i1 ...`) is not supported.

Ill-formed UTF-8 in string values and object keys

UBJSON's required string encoding is UTF-8, but checking it on read is opt-in: with the [`error_handler`](https://json.nlohmann.me/api/basic_json/from_ubjson/index.md) parameter left at `keep` (the default), `from_ubjson()` accepts a string value or object key whose bytes are not valid UTF-8 and hands them back unchanged. Passing `error_handler_t::strict` makes `from_ubjson()` check and throw [`parse_error.113`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error113) for ill-formed UTF-8, and `replace`/`ignore` sanitize the string instead of keeping it. However, [`dump()`](https://json.nlohmann.me/api/basic_json/dump/index.md) still requires valid UTF-8 and throws [`type_error.316`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error316) for a value read with the default `keep` handler, unless an error handler is passed that replaces or ignores the ill-formed bytes. `to_ubjson()`'s own `error_handler` parameter defaults to `keep` (see above), so such a value is written back unchanged.

Example: deserialize a JSON value from UBJSON

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

    // deserialize it with UBJSON
    json j = json::from_ubjson(v);

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
