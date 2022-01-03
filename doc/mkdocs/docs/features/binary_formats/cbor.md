# CBOR

The Concise Binary Object Representation (CBOR) is a data format whose design goals include the possibility of extremely
small code size, fairly small message size, and extensibility without the need for version negotiation.

!!! abstract "References"

  	- [CBOR Website](http://cbor.io) - the main source on CBOR
    - [CBOR Playground](http://cbor.me) - an interactive webpage to translate between JSON and CBOR
    - [RFC 7049](https://tools.ietf.org/html/rfc7049) - the CBOR specification

## Serialization

The library uses the following mapping from JSON values types to CBOR types according to the CBOR specification (RFC 7049):

| JSON value type | value/range                                | CBOR type                         | first byte |
|-----------------|--------------------------------------------|-----------------------------------|------------|
| null            | `null`                                     | Null                              | 0xF6       |
| boolean         | `true`                                     | True                              | 0xF5       |
| boolean         | `false`                                    | False                             | 0xF4       |
| number_integer  | -9223372036854775808..-2147483649          | Negative integer (8 bytes follow) | 0x3B       |
| number_integer  | -2147483648..-32769                        | Negative integer (4 bytes follow) | 0x3A       |
| number_integer  | -32768..-129                               | Negative integer (2 bytes follow) | 0x39       |
| number_integer  | -128..-25                                  | Negative integer (1 byte follow)  | 0x38       |
| number_integer  | -24..-1                                    | Negative integer                  | 0x20..0x37 |
| number_integer  | 0..23                                      | Integer                           | 0x00..0x17 |
| number_integer  | 24..255                                    | Unsigned integer (1 byte follow)  | 0x18       |
| number_integer  | 256..65535                                 | Unsigned integer (2 bytes follow) | 0x19       |
| number_integer  | 65536..4294967295                          | Unsigned integer (4 bytes follow) | 0x1A       |
| number_integer  | 4294967296..18446744073709551615           | Unsigned integer (8 bytes follow) | 0x1B       |
| number_unsigned | 0..23                                      | Integer                           | 0x00..0x17 |
| number_unsigned | 24..255                                    | Unsigned integer (1 byte follow)  | 0x18       |
| number_unsigned | 256..65535                                 | Unsigned integer (2 bytes follow) | 0x19       |
| number_unsigned | 65536..4294967295                          | Unsigned integer (4 bytes follow) | 0x1A       |
| number_unsigned | 4294967296..18446744073709551615           | Unsigned integer (8 bytes follow) | 0x1B       |
| number_float    | *any value representable by a float*       | Single-Precision Float            | 0xFA       |
| number_float    | *any value NOT representable by a float*   | Double-Precision Float            | 0xFB       |
| string          | *length*: 0..23                            | UTF-8 string                      | 0x60..0x77 |
| string          | *length*: 23..255                          | UTF-8 string (1 byte follow)      | 0x78       |
| string          | *length*: 256..65535                       | UTF-8 string (2 bytes follow)     | 0x79       |
| string          | *length*: 65536..4294967295                | UTF-8 string (4 bytes follow)     | 0x7A       |
| string          | *length*: 4294967296..18446744073709551615 | UTF-8 string (8 bytes follow)     | 0x7B       |
| array           | *size*: 0..23                              | array                             | 0x80..0x97 |
| array           | *size*: 23..255                            | array (1 byte follow)             | 0x98       |
| array           | *size*: 256..65535                         | array (2 bytes follow)            | 0x99       |
| array           | *size*: 65536..4294967295                  | array (4 bytes follow)            | 0x9A       |
| array           | *size*: 4294967296..18446744073709551615   | array (8 bytes follow)            | 0x9B       |
| object          | *size*: 0..23                              | map                               | 0xA0..0xB7 |
| object          | *size*: 23..255                            | map (1 byte follow)               | 0xB8       |
| object          | *size*: 256..65535                         | map (2 bytes follow)              | 0xB9       |
| object          | *size*: 65536..4294967295                  | map (4 bytes follow)              | 0xBA       |
| object          | *size*: 4294967296..18446744073709551615   | map (8 bytes follow)              | 0xBB       |
| binary          | *size*: 0..23                              | byte string                       | 0x40..0x57 |
| binary          | *size*: 23..255                            | byte string (1 byte follow)       | 0x58       |
| binary          | *size*: 256..65535                         | byte string (2 bytes follow)      | 0x59       |
| binary          | *size*: 65536..4294967295                  | byte string (4 bytes follow)      | 0x5A       |
| binary          | *size*: 4294967296..18446744073709551615   | byte string (8 bytes follow)      | 0x5B       |

Binary values with subtype are mapped to tagged values (0xD8..0xDB) depending on the subtype, followed by a byte string,
see "binary" cells in the table above.

!!! success "Complete mapping"

	The mapping is **complete** in the sense that any JSON value type can be converted to a CBOR value.

!!! info "NaN/infinity handling"

	If NaN or Infinity are stored inside a JSON number, they are serialized properly. This behavior differs from the normal JSON serialization which serializes NaN or Infinity to `null`.

!!! info "Unused CBOR types"

	The following CBOR types are not used in the conversion:

      - UTF-8 strings terminated by "break" (0x7F)
      - arrays terminated by "break" (0x9F)
      - maps terminated by "break" (0xBF)
      - byte strings terminated by "break" (0x5F)
      - date/time (0xC0..0xC1)
      - bignum (0xC2..0xC3)
      - decimal fraction (0xC4)
      - bigfloat (0xC5)
      - expected conversions (0xD5..0xD7)
      - simple values (0xE0..0xF3, 0xF8)
      - undefined (0xF7)
      - half-precision floats (0xF9)
      - break (0xFF)

!!! info "Tagged items"

    Binary subtypes will be serialized as tagged items. See [binary values](../binary_values.md#cbor) for an example.

??? example

    ```cpp
    --8<-- "examples/to_cbor.cpp"
    ```
    
    Output:

    ```c
    --8<-- "examples/to_cbor.output"
    ```

## Deserialization

The library maps CBOR types to JSON value types as follows:

| CBOR type              | JSON value type | first byte |
|------------------------|-----------------|------------|
| Integer                | number_unsigned | 0x00..0x17 |
| Unsigned integer       | number_unsigned | 0x18       |
| Unsigned integer       | number_unsigned | 0x19       |
| Unsigned integer       | number_unsigned | 0x1A       |
| Unsigned integer       | number_unsigned | 0x1B       |
| Negative integer       | number_integer  | 0x20..0x37 |
| Negative integer       | number_integer  | 0x38       |
| Negative integer       | number_integer  | 0x39       |
| Negative integer       | number_integer  | 0x3A       |
| Negative integer       | number_integer  | 0x3B       |
| Byte string            | binary          | 0x40..0x57 |
| Byte string            | binary          | 0x58       |
| Byte string            | binary          | 0x59       |
| Byte string            | binary          | 0x5A       |
| Byte string            | binary          | 0x5B       |
| UTF-8 string           | string          | 0x60..0x77 |
| UTF-8 string           | string          | 0x78       |
| UTF-8 string           | string          | 0x79       |
| UTF-8 string           | string          | 0x7A       |
| UTF-8 string           | string          | 0x7B       |
| UTF-8 string           | string          | 0x7F       |
| array                  | array           | 0x80..0x97 |
| array                  | array           | 0x98       |
| array                  | array           | 0x99       |
| array                  | array           | 0x9A       |
| array                  | array           | 0x9B       |
| array                  | array           | 0x9F       |
| map                    | object          | 0xA0..0xB7 |
| map                    | object          | 0xB8       |
| map                    | object          | 0xB9       |
| map                    | object          | 0xBA       |
| map                    | object          | 0xBB       |
| map                    | object          | 0xBF       |
| False                  | `false`         | 0xF4       |
| True                   | `true`          | 0xF5       |
| Null                   | `null`          | 0xF6       |
| Half-Precision Float   | number_float    | 0xF9       |
| Single-Precision Float | number_float    | 0xFA       |
| Double-Precision Float | number_float    | 0xFB       |

!!! warning "Incomplete mapping"

	The mapping is **incomplete** in the sense that not all CBOR types can be converted to a JSON value. The following CBOR types are not supported and will yield parse errors:

     - date/time (0xC0..0xC1)
     - bignum (0xC2..0xC3)
     - decimal fraction (0xC4)
     - bigfloat (0xC5)
     - expected conversions (0xD5..0xD7)
     - simple values (0xE0..0xF3, 0xF8)
     - undefined (0xF7)

!!! warning "Object keys"

	CBOR allows map keys of any type, whereas JSON only allows strings as keys in object values. Therefore, CBOR maps with keys other than UTF-8 strings are rejected.

!!! warning "Tagged items"

    Tagged items will throw a parse error by default. They can be ignored by passing `cbor_tag_handler_t::ignore` to function `from_cbor`. They can be stored by passing `cbor_tag_handler_t::store` to function `from_cbor`.

??? example

    ```cpp
    --8<-- "examples/from_cbor.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/from_cbor.output"
    ```
