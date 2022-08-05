# MessagePack

MessagePack is an efficient binary serialization format. It lets you exchange data among multiple languages like JSON.
But it's faster and smaller. Small integers are encoded into a single byte, and typical short strings require only one
extra byte in addition to the strings themselves.

!!! abstract "References"

    - [MessagePack website](https://msgpack.org)
    - [MessagePack specification](https://github.com/msgpack/msgpack/blob/master/spec.md)

## Serialization

The library uses the following mapping from JSON values types to MessagePack types according to the MessagePack
specification:

| JSON value type | value/range                              | MessagePack type | first byte |
|-----------------|------------------------------------------|------------------|------------|
| null            | `null`                                   | nil              | 0xC0       |
| boolean         | `true`                                   | true             | 0xC3       |
| boolean         | `false`                                  | false            | 0xC2       |
| number_integer  | -9223372036854775808..-2147483649        | int64            | 0xD3       |
| number_integer  | -2147483648..-32769                      | int32            | 0xD2       |
| number_integer  | -32768..-129                             | int16            | 0xD1       |
| number_integer  | -128..-33                                | int8             | 0xD0       |
| number_integer  | -32..-1                                  | negative fixint  | 0xE0..0xFF |
| number_integer  | 0..127                                   | positive fixint  | 0x00..0x7F |
| number_integer  | 128..255                                 | uint 8           | 0xCC       |
| number_integer  | 256..65535                               | uint 16          | 0xCD       |
| number_integer  | 65536..4294967295                        | uint 32          | 0xCE       |
| number_integer  | 4294967296..18446744073709551615         | uint 64          | 0xCF       |
| number_unsigned | 0..127                                   | positive fixint  | 0x00..0x7F |
| number_unsigned | 128..255                                 | uint 8           | 0xCC       |
| number_unsigned | 256..65535                               | uint 16          | 0xCD       |
| number_unsigned | 65536..4294967295                        | uint 32          | 0xCE       |
| number_unsigned | 4294967296..18446744073709551615         | uint 64          | 0xCF       |
| number_float    | *any value representable by a float*     | float 32         | 0xCA       |
| number_float    | *any value NOT representable by a float* | float 64         | 0xCB       |
| string          | *length*: 0..31                          | fixstr           | 0xA0..0xBF |
| string          | *length*: 32..255                        | str 8            | 0xD9       |
| string          | *length*: 256..65535                     | str 16           | 0xDA       |
| string          | *length*: 65536..4294967295              | str 32           | 0xDB       |
| array           | *size*: 0..15                            | fixarray         | 0x90..0x9F |
| array           | *size*: 16..65535                        | array 16         | 0xDC       |
| array           | *size*: 65536..4294967295                | array 32         | 0xDD       |
| object          | *size*: 0..15                            | fix map          | 0x80..0x8F |
| object          | *size*: 16..65535                        | map 16           | 0xDE       |
| object          | *size*: 65536..4294967295                | map 32           | 0xDF       |
| binary          | *size*: 0..255                           | bin 8            | 0xC4       |
| binary          | *size*: 256..65535                       | bin 16           | 0xC5       |
| binary          | *size*: 65536..4294967295                | bin 32           | 0xC6       |

!!! success "Complete mapping"

    The mapping is **complete** in the sense that any JSON value type can be converted to a MessagePack value.

    Any MessagePack output created by `to_msgpack` can be successfully parsed by `from_msgpack`.

!!! warning "Size constraints"

    The following values can **not** be converted to a MessagePack value:

      - strings with more than 4294967295 bytes
      - byte strings with more than 4294967295 bytes
      - arrays with more than 4294967295 elements
      - objects with more than 4294967295 elements

!!! info "NaN/infinity handling"

    If NaN or Infinity are stored inside a JSON number, they are serialized properly in contrast to the
    [dump](../../api/basic_json/dump.md) function which serializes NaN or Infinity to `null`.

??? example

    ```cpp
    --8<-- "examples/to_msgpack.cpp"
    ```
    
    Output:

    ```c
    --8<-- "examples/to_msgpack.output"
    ```

## Deserialization

The library maps MessagePack types to JSON value types as follows:

| MessagePack type | JSON value type | first byte |
|------------------|-----------------|------------|
| positive fixint  | number_unsigned | 0x00..0x7F |
| fixmap           | object          | 0x80..0x8F |
| fixarray         | array           | 0x90..0x9F |
| fixstr           | string          | 0xA0..0xBF |
| nil              | `null`          | 0xC0       |
| false            | `false`         | 0xC2       |
| true             | `true`          | 0xC3       |
| float 32         | number_float    | 0xCA       |
| float 64         | number_float    | 0xCB       |
| uint 8           | number_unsigned | 0xCC       |
| uint 16          | number_unsigned | 0xCD       |
| uint 32          | number_unsigned | 0xCE       |
| uint 64          | number_unsigned | 0xCF       |
| int 8            | number_integer  | 0xD0       |
| int 16           | number_integer  | 0xD1       |
| int 32           | number_integer  | 0xD2       |
| int 64           | number_integer  | 0xD3       |
| str 8            | string          | 0xD9       |
| str 16           | string          | 0xDA       |
| str 32           | string          | 0xDB       |
| array 16         | array           | 0xDC       |
| array 32         | array           | 0xDD       |
| map 16           | object          | 0xDE       |
| map 32           | object          | 0xDF       |
| bin 8            | binary          | 0xC4       |
| bin 16           | binary          | 0xC5       |
| bin 32           | binary          | 0xC6       |
| ext 8            | binary          | 0xC7       |
| ext 16           | binary          | 0xC8       |
| ext 32           | binary          | 0xC9       |
| fixext 1         | binary          | 0xD4       |
| fixext 2         | binary          | 0xD5       |
| fixext 4         | binary          | 0xD6       |
| fixext 8         | binary          | 0xD7       |
| fixext 16        | binary          | 0xD8       |
| negative fixint  | number_integer  | 0xE0-0xFF  |

!!! info

    Any MessagePack output created by `to_msgpack` can be successfully parsed by `from_msgpack`.


??? example

    ```cpp
    --8<-- "examples/from_msgpack.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/from_msgpack.output"
    ```
