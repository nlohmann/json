# BON8

BON8 (Binary Object Notation 8) is a compact binary serialization format for JSON values. It uses the byte values that
cannot begin a UTF-8 character as type markers, so strings are stored as plain UTF-8 without a length prefix: a string
ends at the first byte that cannot continue it. Integers from -10 to 39, `true`, `false`, `null`, and the floating-point
values -1.0, 0.0, and 1.0 take a single byte, and arrays and objects with up to four elements need no terminator.

!!! abstract "References"

    - [BON8 specification](https://github.com/hikoworks/hikogui/blob/main/docs/BON8.md)
    - [Reference implementation](https://github.com/hikoworks/hikogui/blob/main/src/hikogui/codec/BON8.hpp) in HikoGUI

## Serialization

The library uses the following mapping from JSON values types to BON8 types according to the BON8 specification:

| JSON value type | value/range                                  | BON8 type                     | first byte |
|-----------------|----------------------------------------------|-------------------------------|------------|
| null            | `null`                                       | null                          | 0xFA       |
| boolean         | `true`                                       | true                          | 0xF9       |
| boolean         | `false`                                      | false                         | 0xF8       |
| number_integer  | -9223372036854775808..-2147483649            | int64                         | 0x8D       |
| number_integer  | -2147483648..-33818507                       | int32                         | 0x8C       |
| number_integer  | -33818506..-264075                           | 4-byte negative integer       | 0xF0..0xF7 |
| number_integer  | -264074..-1931                               | 3-byte negative integer       | 0xE0..0xEF |
| number_integer  | -1930..-11                                   | 2-byte negative integer       | 0xC2..0xDF |
| number_integer  | -10..-1                                      | 1-byte negative integer       | 0xB8..0xC1 |
| number_integer  | 0..39                                        | 1-byte positive integer       | 0x90..0xB7 |
| number_integer  | 40..3879                                     | 2-byte positive integer       | 0xC2..0xDF |
| number_integer  | 3880..528167                                 | 3-byte positive integer       | 0xE0..0xEF |
| number_integer  | 528168..67637031                             | 4-byte positive integer       | 0xF0..0xF7 |
| number_integer  | 67637032..2147483647                         | int32                         | 0x8C       |
| number_integer  | 2147483648..9223372036854775807              | int64                         | 0x8D       |
| number_unsigned | 0..39                                        | 1-byte positive integer       | 0x90..0xB7 |
| number_unsigned | 40..3879                                     | 2-byte positive integer       | 0xC2..0xDF |
| number_unsigned | 3880..528167                                 | 3-byte positive integer       | 0xE0..0xEF |
| number_unsigned | 528168..67637031                             | 4-byte positive integer       | 0xF0..0xF7 |
| number_unsigned | 67637032..2147483647                         | int32                         | 0x8C       |
| number_unsigned | 2147483648..9223372036854775807              | int64                         | 0x8D       |
| number_float    | `-1.0`                                       | -1.0                          | 0xFB       |
| number_float    | `0.0`                                        | 0.0                           | 0xFC       |
| number_float    | `1.0`                                        | 1.0                           | 0xFD       |
| number_float    | *any other value representable by a float*   | binary32                      | 0x8E       |
| number_float    | *any value NOT representable by a float*     | binary64                      | 0x8F       |
| string          | *empty*                                      | end of string                 | 0xFF       |
| string          | *non-empty*                                  | UTF-8 string                  | 0x00..0x7F, 0xC2..0xF4 |
| array           | *size*: 0..4                                 | array with count              | 0x80..0x84 |
| array           | *size*: 5 or more                            | array (terminated by 0xFE)    | 0x85       |
| object          | *size*: 0..4                                 | object with count             | 0x86..0x8A |
| object          | *size*: 5 or more                            | object (terminated by 0xFE)   | 0x8B       |
| binary          | *size*: 0..4                                 | array with count              | 0x80..0x84 |
| binary          | *size*: 5 or more                            | array (terminated by 0xFE)    | 0x85       |

An integer that takes 2 to 4 bytes starts with a UTF-8 lead byte (0xC2..0xF7) that is followed by a byte that cannot
continue a UTF-8 character: 0x00..0x7F for positive and 0xC0..0xFF for negative integers. A string is terminated by
0xFF only if it is empty, if another string follows it, or if it is the last value of the message; otherwise, the first
byte of the next value ends it.

!!! success "Complete mapping"

    Except for the values listed below, any JSON value can be converted to a BON8 value.

    Any BON8 output created by `to_bon8` can be successfully parsed by `from_bon8`.

!!! warning "Unsupported values"

    The following values can **not** be converted to a BON8 value:

      - unsigned integers above 9223372036854775807, because BON8 has no unsigned 64-bit integer type
        ([out_of_range.407](../../home/exceptions.md#jsonexceptionout_of_range407))
      - strings that are not valid UTF-8, because the end of a string is determined from its encoding
        ([type_error.316](../../home/exceptions.md#jsonexceptiontype_error316))

!!! info "NaN/infinity handling"

    `-0.0`, `Infinity`, and `-Infinity` are serialized as binary32 (type 0x8E, 5 bytes total). `NaN` is serialized as
    the binary32 value 0x7F800001 that the specification recommends. This is in contrast to the
    [dump](../../api/basic_json/dump.md) function which serializes NaN or Infinity to `null`.

!!! warning "Binary values"

    BON8 has no binary type. Binary values are serialized as arrays of integers (0..255), so they are read back as
    arrays. The subtype is not serialized.

!!! info "Canonical representation"

    The output follows the specification's canonical representation rules: every value uses the shortest encoding,
    floating-point numbers use binary32 whenever that loses no precision, and object keys are sorted by their UTF-8
    code units. There are two exceptions:

    - Strings are not normalized to Unicode Normalization Form C (NFC).
    - Object keys are written in the order of the object type, which is sorted for `json`, but not for
      [`ordered_json`](../../api/ordered_json.md).

??? example

    ```cpp
    --8<-- "examples/to_bon8.cpp"
    ```

    Output:

    ```c
    --8<-- "examples/to_bon8.output"
    ```

## Deserialization

The library maps BON8 types to JSON value types as follows:

| BON8 type                     | JSON value type | first byte             |
|-------------------------------|-----------------|------------------------|
| UTF-8 string                  | string          | 0x00..0x7F             |
| array with count              | array           | 0x80..0x84             |
| array (terminated by 0xFE)    | array           | 0x85                   |
| object with count             | object          | 0x86..0x8A             |
| object (terminated by 0xFE)   | object          | 0x8B                   |
| int32                         | number_unsigned or number_integer | 0x8C |
| int64                         | number_unsigned or number_integer | 0x8D |
| binary32                      | number_float    | 0x8E                   |
| binary64                      | number_float    | 0x8F                   |
| 1-byte positive integer       | number_unsigned | 0x90..0xB7             |
| 1-byte negative integer       | number_integer  | 0xB8..0xC1             |
| UTF-8 string                  | string          | 0xC2..0xF4, followed by 0x80..0xBF |
| 2- to 4-byte positive integer | number_unsigned | 0xC2..0xF7, followed by 0x00..0x7F |
| 2- to 4-byte negative integer | number_integer  | 0xC2..0xF7, followed by 0xC0..0xFF |
| false                         | `false`         | 0xF8                   |
| true                          | `true`          | 0xF9                   |
| null                          | `null`          | 0xFA                   |
| -1.0                          | number_float    | 0xFB                   |
| 0.0                           | number_float    | 0xFC                   |
| 1.0                           | number_float    | 0xFD                   |
| empty string                  | string          | 0xFF                   |

Non-negative integers are read as number_unsigned, negative integers as number_integer.

!!! info

    Values that do not use the canonical representation, such as integers with a longer encoding than necessary,
    arrays and objects with up to four elements that are terminated by 0xFE, unsorted object keys, or a 0xFF after a
    string that would also end without it, are accepted. A second 0xFF is not a terminator but an empty string.

    Strings must be valid UTF-8, and the last string of a message must be terminated by 0xFF.

!!! info

    Any BON8 output created by `to_bon8` can be successfully parsed by `from_bon8`.

??? example

    ```cpp
    --8<-- "examples/from_bon8.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/from_bon8.output"
    ```
