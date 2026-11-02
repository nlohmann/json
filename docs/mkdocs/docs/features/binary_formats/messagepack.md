# MessagePack

MessagePack is an efficient binary serialization format. It lets you exchange data among multiple languages like JSON.
But it's faster and smaller. Small integers are encoded into a single byte, and typical short strings require only one
extra byte in addition to the strings themselves.

!!! abstract "References"

    - [MessagePack website](https://msgpack.org)
    - [MessagePack specification](https://github.com/msgpack/msgpack/blob/master/spec.md)

## Byte layout

MessagePack encodes each value as a one-byte *format marker*, optionally followed by a length or the payload. The marker range is partitioned to keep common values small: small non-negative integers (0 to 127) and small negative integers (-32 to -1) are the marker byte itself; short strings, arrays, and maps (up to 31 bytes for strings and up to 15 elements for arrays and maps) hide their length in the marker's lower bits. Larger values use dedicated markers that announce the width (8, 16, 32, or 64 bits) of the length or number that follows, in big-endian byte order. Like CBOR, containers are length-prefixed, so no terminator is needed.

Consider the following JSON value (shown formatted for readability):

```json
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

`to_msgpack` encodes it to 39 bytes (shown in hexadecimal; the encoding contains no whitespace). The colors mark the role of each byte: <span class="bl bl-t">type/marker</span> <span class="bl bl-d">data</span>.

<div class="byte-layout" markdown="0"><table>
<thead><tr><th>JSON</th><th>Bytes</th><th>Meaning</th></tr></thead><tbody>
<tr><td><code>{</code></td><td><span class="bl bl-t">84</span></td><td>map with 4 key/value pairs</td></tr>
<tr><td><code>&quot;id&quot;: 300,</code></td><td><span class="bl bl-t">A2</span> <span class="bl bl-d">69 64</span> <span class="bl bl-t">CD</span> <span class="bl bl-d">01 2C</span></td><td>key: fixstr of length 2, then its UTF-8 bytes; value: uint 16 (big-endian)</td></tr>
<tr><td><code>&quot;name&quot;: &quot;json&quot;,</code></td><td><span class="bl bl-t">A4</span> <span class="bl bl-d">6E 61 6D 65</span> <span class="bl bl-t">A4</span> <span class="bl bl-d">6A 73 6F 6E</span></td><td>key: fixstr of length 4; value: fixstr of length 4</td></tr>
<tr><td><code>&quot;pi&quot;: 3.14,</code></td><td><span class="bl bl-t">A2</span> <span class="bl bl-d">70 69</span> <span class="bl bl-t">CB</span> <span class="bl bl-d">40 09 1E B8 51 EB 85 1F</span></td><td>key: fixstr of length 2; value: float 64 (IEEE 754, big-endian)</td></tr>
<tr><td><code>&quot;tags&quot;: [</code></td><td><span class="bl bl-t">A4</span> <span class="bl bl-d">74 61 67 73</span> <span class="bl bl-t">92</span></td><td>key: fixstr of length 4; value: fixarray with 2 elements</td></tr>
<tr><td><code>&quot;a&quot;,</code></td><td><span class="bl bl-t">A1</span> <span class="bl bl-d">61</span></td><td>fixstr of length 1</td></tr>
<tr><td><code>&quot;b&quot;</code></td><td><span class="bl bl-t">A1</span> <span class="bl bl-d">62</span></td><td>fixstr of length 1</td></tr>
<tr><td><code>]</code></td><td></td><td>no end marker: the element count was given up front</td></tr>
<tr><td><code>}</code></td><td></td><td>no end marker: the member count was given up front</td></tr>
</tbody></table></div>

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

    Serializing such a value throws [`out_of_range.412`](../../home/exceptions.md#jsonexceptionout_of_range412).

!!! info "NaN/infinity handling"

    `NaN`, `Infinity`, and `-Infinity` are serialized as a MessagePack float 32 (type 0xCA, 5 bytes total),
    regardless of magnitude, in contrast to the [dump](../../api/basic_json/dump.md) function which serializes NaN
    or Infinity to `null`.

!!! note

    Prior to version 3.13.0, NaN and Infinity were instead serialized as a MessagePack float 64 (type 0xCB, 9 bytes
    total), because the check used to select the smaller float 32 encoding failed for NaN (all comparisons are `false`)
    and for Infinity and -Infinity (outside the float range checked against `std::numeric_limits<float>::lowest()` and
    `max()`), so the float 32 path was skipped.

??? example "Example: serialize a JSON value to MessagePack"

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
| (never used)     | –               | 0xC1       |
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

The byte 0xC1 is reserved as "never used" by the specification. As a value it is rejected with
[`parse_error.112`](../../home/exceptions.md#jsonexceptionparse_error112) (`invalid byte: 0xC1`); as a map key it is
rejected with [`parse_error.113`](../../home/exceptions.md#jsonexceptionparse_error113) and the generic "expected length
specification" message, because the key is read as a string.

Duplicate keys in a map are accepted; the last value wins.

### Extension types (ext, fixext)

MessagePack ext and fixext values are read as binary values, and the ext type byte is stored as the binary subtype.
Although the specification defines the type as a signed 8-bit integer (0 to 127 for applications, -128 to -1 reserved,
with -1 being the Timestamp extension), the library reads it as an unsigned byte: a negative ext type `n` becomes
subtype `256+n`, so ext type -1 is read as subtype 255 and -128 as subtype 128. The Timestamp extension is not
interpreted; it is returned as binary with subtype 255. Use
[`has_subtype()`](../../api/byte_container_with_subtype/has_subtype.md) to tell a `bin` value (no subtype) from an ext
value (subtype, even if it is 0).

When serializing, a binary value with a subtype is always written as fixext (1, 2, 4, 8, or 16 bytes) or ext, even
for subtype 0 (`d6 00 01 02 03 04`); a binary value without a subtype is written as bin. Subtypes 128 to 255 are
written as the reserved negative ext types (255 as -1), so `json::binary({1,2,3,4}, 255)` becomes
`d6 ff 01 02 03 04`, which other MessagePack libraries decode as a 32-bit timestamp. A subtype above 255 throws
[`out_of_range.415`](../../home/exceptions.md#jsonexceptionout_of_range415). The payload length is limited to
4294967295 bytes like all other lengths.

!!! info

    Any MessagePack output created by `to_msgpack` can be successfully parsed by `from_msgpack`.

!!! warning "Object keys"

    MessagePack allows map keys of any type, whereas JSON only allows strings as keys in object values. Like the
    JSON-compatible [profile](https://github.com/msgpack/msgpack/blob/master/spec.md#profile) sketched in the
    MessagePack specification, this library restricts map keys to `str` values. Maps with keys of any other type are
    rejected with a [`parse_error.113`](../../home/exceptions.md#jsonexceptionparse_error113) exception (or, with
    `allow_exceptions` set to `false`, a discarded value). For most key types the message names the type that was
    found, for instance:

    ```
    [json.exception.parse_error.113] parse error at byte 2: syntax error while parsing MessagePack object key: only string keys are supported, but found nil; last byte: 0xC0
    ```

    This applies to the [SAX interface](../parsing/sax_interface.md) as well, as the key is read before it is passed
    on. Such input needs a general-purpose MessagePack library instead.

!!! warning "Ill-formed UTF-8 in string values"

    The MessagePack specification explicitly allows a `str` value (`fixstr`, `str 8`, `str 16`, `str 32`) to contain
    a byte sequence that is not valid UTF-8, and recommends that a deserializer provide a way to obtain the original bytes.
    This library follows that by default: with its
    [`error_handler`](../../api/basic_json/from_msgpack.md) parameter left at `keep` (the default),
    `from_msgpack()` reads `str` bytes (object keys included) as-is, without validating them, so such a value
    round-trips through `from_msgpack(to_msgpack(j))` byte for byte. Passing `error_handler_t::strict` makes
    `from_msgpack()` check anyway and throw
    [`parse_error.113`](../../home/exceptions.md#jsonexceptionparse_error113) for ill-formed UTF-8, and
    `replace`/`ignore` sanitize the string instead of keeping it. `to_msgpack()` also writes `str` bytes as-is by
    default, since the specification permits it; its [`error_handler`](../../api/basic_json/to_msgpack.md) parameter
    can be set to `strict` to throw [`type_error.316`](../../home/exceptions.md#jsonexceptiontype_error316) instead, or
    to `replace`/`ignore` to sanitize the string, for instance for a decoder that rejects ill-formed UTF-8. However,
    [`dump()`](../../api/basic_json/dump.md) still requires valid UTF-8 and throws
    [`type_error.316`](../../home/exceptions.md#jsonexceptiontype_error316) for a value read this way with the
    default `keep` handler, unless an error handler is passed that replaces or ignores the ill-formed bytes.

??? example "Example: deserialize a JSON value from MessagePack"

    ```cpp
    --8<-- "examples/from_msgpack.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/from_msgpack.output"
    ```

## See also

- [Binary formats](index.md) - overview and comparison of the supported binary formats
- [Binary values](../binary_values.md) - how binary values and subtypes map to MessagePack
- [`to_msgpack`](../../api/basic_json/to_msgpack.md) - serialize a JSON value to MessagePack
- [`from_msgpack`](../../api/basic_json/from_msgpack.md) - parse a JSON value from MessagePack
- [`JSON_STRICT_BINARY_UTF8`](../../api/macros/json_strict_binary_utf8.md) - reject ill-formed UTF-8 in strings
- [SAX interface](../parsing/sax_interface.md) - decode binary formats without building a value
