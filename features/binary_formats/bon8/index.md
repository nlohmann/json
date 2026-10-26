# BON8

BON8 (Binary Object Notation 8) is a compact binary serialization format for JSON values. It uses byte values that cannot begin a UTF-8 character as type markers, so strings are stored as plain UTF-8 without a length prefix: a string ends at the first byte that cannot continue it. Integers from -10 to 39, `true`, `false`, `null`, and the floating-point values -1.0, 0.0, and 1.0 take a single byte, and arrays and objects with up to four elements need no terminator.

References

- [BON8 specification](https://github.com/hikoworks/hikogui/blob/main/docs/BON8.md)
- [Reference implementation](https://github.com/hikoworks/hikogui/blob/main/src/hikogui/codec/BON8.hpp) in HikoGUI

## Byte layout

BON8 exploits the fact that some byte values can never start a UTF-8 character. These bytes serve as *type markers*, so strings can be stored as plain UTF-8 without a length prefix: a string ends at the first byte that cannot continue it: a marker byte, or a lead byte 0xC2..0xF7 followed by a byte outside 0x80..0xBF. The ending byte is often the marker of the next value. Small integers, `true`, `false`, `null`, and a few common floats are a single byte. Arrays and objects are introduced by a marker; those with up to four elements encode their size in the marker and need no terminator, while larger ones are closed by the end marker `0xFE`.

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

`to_bon8` encodes it to 35 bytes (shown in hexadecimal; the encoding contains no whitespace). The colors mark the role of each byte: type/marker length/count/size data.

| JSON              | Bytes                            | Meaning                                                                                                                                                                                                     |
| ----------------- | -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `{`               | 8A                               | object with 4 members                                                                                                                                                                                       |
| `"id": 300,`      | 69 64 C4 04                      | key: UTF-8 bytes; the string ends at 0xC4, because the byte after it (0x04) is not a UTF-8 continuation byte, so 0xC4 starts an integer; value: 2-byte positive integer (lead byte, then a byte below 0x80) |
| `"name": "json",` | 6E 61 6D 65 FF 6A 73 6F 6E FF    | key: UTF-8 bytes; 0xFF terminates the string as another string follows; value: UTF-8 bytes; terminated as a string key follows                                                                              |
| `"pi": 3.14,`     | 70 69 8F 40 09 1E B8 51 EB 85 1F | key: UTF-8 bytes; value: binary64 (IEEE 754, big-endian); its marker also ends `"pi"`                                                                                                                       |
| `"tags": [`       | 74 61 67 73 82                   | key: UTF-8 bytes; value: array with 2 elements; its marker also ends `"tags"`                                                                                                                               |
| `"a",`            | 61 FF                            | UTF-8 bytes; terminated as a string follows                                                                                                                                                                 |
| `"b"`             | 62 FF                            | UTF-8 bytes; terminated as nothing follows                                                                                                                                                                  |
| `]`               |                                  | no end marker: the element count was given up front                                                                                                                                                         |
| `}`               |                                  | no end marker: the member count was given up front                                                                                                                                                          |

## Serialization

The library uses the following mapping from JSON values types to BON8 types according to the BON8 specification:

| JSON value type | value/range                                | BON8 type                   | first byte             |
| --------------- | ------------------------------------------ | --------------------------- | ---------------------- |
| null            | `null`                                     | null                        | 0xFA                   |
| boolean         | `true`                                     | true                        | 0xF9                   |
| boolean         | `false`                                    | false                       | 0xF8                   |
| number_integer  | -9223372036854775808..-2147483649          | int64                       | 0x8D                   |
| number_integer  | -2147483648..-33818507                     | int32                       | 0x8C                   |
| number_integer  | -33818506..-264075                         | 4-byte negative integer     | 0xF0..0xF7             |
| number_integer  | -264074..-1931                             | 3-byte negative integer     | 0xE0..0xEF             |
| number_integer  | -1930..-11                                 | 2-byte negative integer     | 0xC2..0xDF             |
| number_integer  | -10..-1                                    | 1-byte negative integer     | 0xB8..0xC1             |
| number_integer  | 0..39                                      | 1-byte positive integer     | 0x90..0xB7             |
| number_integer  | 40..3879                                   | 2-byte positive integer     | 0xC2..0xDF             |
| number_integer  | 3880..528167                               | 3-byte positive integer     | 0xE0..0xEF             |
| number_integer  | 528168..67637031                           | 4-byte positive integer     | 0xF0..0xF7             |
| number_integer  | 67637032..2147483647                       | int32                       | 0x8C                   |
| number_integer  | 2147483648..9223372036854775807            | int64                       | 0x8D                   |
| number_unsigned | 0..39                                      | 1-byte positive integer     | 0x90..0xB7             |
| number_unsigned | 40..3879                                   | 2-byte positive integer     | 0xC2..0xDF             |
| number_unsigned | 3880..528167                               | 3-byte positive integer     | 0xE0..0xEF             |
| number_unsigned | 528168..67637031                           | 4-byte positive integer     | 0xF0..0xF7             |
| number_unsigned | 67637032..2147483647                       | int32                       | 0x8C                   |
| number_unsigned | 2147483648..9223372036854775807            | int64                       | 0x8D                   |
| number_float    | `-1.0`                                     | -1.0                        | 0xFB                   |
| number_float    | `0.0`                                      | 0.0                         | 0xFC                   |
| number_float    | `1.0`                                      | 1.0                         | 0xFD                   |
| number_float    | *any other value representable by a float* | binary32                    | 0x8E                   |
| number_float    | *any value NOT representable by a float*   | binary64                    | 0x8F                   |
| string          | *empty*                                    | end of string               | 0xFF                   |
| string          | *non-empty*                                | UTF-8 string                | 0x00..0x7F, 0xC2..0xF4 |
| array           | *size*: 0..4                               | array with count            | 0x80..0x84             |
| array           | *size*: 5 or more                          | array (terminated by 0xFE)  | 0x85                   |
| object          | *size*: 0..4                               | object with count           | 0x86..0x8A             |
| object          | *size*: 5 or more                          | object (terminated by 0xFE) | 0x8B                   |
| binary          | *size*: 0..4                               | array with count            | 0x80..0x84             |
| binary          | *size*: 5 or more                          | array (terminated by 0xFE)  | 0x85                   |

An integer that takes 2 to 4 bytes starts with a UTF-8 lead byte (0xC2..0xF7) that is followed by a byte that cannot continue a UTF-8 character: 0x00..0x7F for positive and 0xC0..0xFF for negative integers. A string is terminated by 0xFF only if it is empty, if another string follows it, or if nothing follows it in the message; otherwise, the byte after it ends it: the first byte of the next value, or the 0xFE that ends an array or object. For example, `["e"]` is serialized as 0x81 0x65 0xFF, but `[1,2,3,4,"e"]` as 0x85 0x91 0x92 0x93 0x94 0x65 0xFE.

Complete mapping

Except for the values listed below, any JSON value can be converted to a BON8 value.

Any BON8 output created by `to_bon8` can be successfully parsed by `from_bon8`.

Unsupported values

The following values can **not** be converted to a BON8 value:

- integers outside the int64 range (unsigned integers above 9223372036854775807 and, for number types wider than 64 bits, any larger or smaller integer), because BON8 integers are limited to int64 ([out_of_range.407](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range407))
- strings that are not valid UTF-8, because the end of a string is determined from its encoding ([type_error.316](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error316))

NaN/infinity handling

`-0.0`, `Infinity`, and `-Infinity` are serialized as binary32 (type 0x8E, 5 bytes total). `NaN` is serialized as the binary32 value 0x7F800001 that the specification recommends. This is in contrast to the [dump](https://json.nlohmann.me/api/basic_json/dump/index.md) function which serializes NaN or Infinity to `null`.

Binary values

BON8 has no binary type. Binary values are serialized as arrays of integers (0..255), so they are read back as arrays. The subtype is not serialized.

Canonical representation

The output follows the specification's canonical representation rules: every value uses the shortest encoding, floating-point numbers use binary32 whenever that loses no precision, and object keys are sorted by their UTF-8 code units. There are two exceptions:

- Strings are not normalized to Unicode Normalization Form C (NFC).
- Object keys are written in the order of the object type, which is sorted for `json`, but not for [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md).

Example: serialize a JSON value to BON8

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using nlohmann::json;
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
        std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
    }
    std::cout << '\n';
}
```

Output:

```
0x89 0x63 0x6f 0x6d 0x70 0x61 0x63 0x74 0xf9 0x66 0x6f 0x72 0x6d 0x61 0x74 0xff 0x42 0x4f 0x4e 0x38 0xff 0x73 0x63 0x68 0x65 0x6d 0x61 0x90
```

## Deserialization

The library maps BON8 types to JSON value types as follows:

| BON8 type                     | JSON value type                   | first byte                         |
| ----------------------------- | --------------------------------- | ---------------------------------- |
| UTF-8 string                  | string                            | 0x00..0x7F                         |
| array with count              | array                             | 0x80..0x84                         |
| array (terminated by 0xFE)    | array                             | 0x85                               |
| object with count             | object                            | 0x86..0x8A                         |
| object (terminated by 0xFE)   | object                            | 0x8B                               |
| int32                         | number_unsigned or number_integer | 0x8C                               |
| int64                         | number_unsigned or number_integer | 0x8D                               |
| binary32                      | number_float                      | 0x8E                               |
| binary64                      | number_float                      | 0x8F                               |
| 1-byte positive integer       | number_unsigned                   | 0x90..0xB7                         |
| 1-byte negative integer       | number_integer                    | 0xB8..0xC1                         |
| UTF-8 string                  | string                            | 0xC2..0xF4, followed by 0x80..0xBF |
| 2- to 4-byte positive integer | number_unsigned                   | 0xC2..0xF7, followed by 0x00..0x7F |
| 2- to 4-byte negative integer | number_integer                    | 0xC2..0xF7, followed by 0xC0..0xFF |
| false                         | `false`                           | 0xF8                               |
| true                          | `true`                            | 0xF9                               |
| null                          | `null`                            | 0xFA                               |
| -1.0                          | number_float                      | 0xFB                               |
| 0.0                           | number_float                      | 0xFC                               |
| 1.0                           | number_float                      | 0xFD                               |
| empty string                  | string                            | 0xFF                               |

Non-negative integers are read as number_unsigned, negative integers as number_integer.

A byte 0xF5..0xF7 followed by 0x80..0xBF is neither a string nor an integer and is rejected with [parse_error.112](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error112) (invalid UTF-8 byte). The same error is reported for any other invalid byte (such as a stray 0xFE), for ill-formed UTF-8, and for an object key that is not a string. Input that ends prematurely, trailing data after the value, and a missing final 0xFF after a string at the end of the message are reported as [parse_error.110](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error110).

Non-canonical input

Values that do not use the canonical representation, such as integers with a longer encoding than necessary, arrays and objects with up to four elements that are terminated by 0xFE, unsorted object keys, or a 0xFF after a string that would also end without it, are accepted. A second 0xFF is not a terminator but an empty string.

Strings must be valid UTF-8, and a string at the very end of a message must be terminated by 0xFF.

Duplicate object keys are accepted; the last value wins (`ordered_json` keeps the position of the first occurrence). The specification does not say how to treat them; the HikoGUI reference decoder keeps the first value.

Round trips

Any BON8 output created by `to_bon8` can be successfully parsed by `from_bon8`.

Example: deserialize a JSON value from BON8

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using nlohmann::json;

int main()
{
    // create byte vector
    std::vector<std::uint8_t> v = {0x89, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x63, 0x74,
                                   0xf9, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0xff,
                                   0x42, 0x4f, 0x4e, 0x38, 0xff, 0x73, 0x63, 0x68,
                                   0x65, 0x6d, 0x61, 0x90
                                  };

    // deserialize it with BON8
    json j = json::from_bon8(v);

    // print the deserialized JSON value
    std::cout << std::setw(2) << j << '\n';
}
```

Output:

```
{
  "compact": true,
  "format": "BON8",
  "schema": 0
}
```
