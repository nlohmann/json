# UBJSON

Universal Binary JSON (UBJSON) is a binary form directly imitating JSON, but requiring fewer bytes of data. It aims to
achieve the generality of JSON, combined with being much easier to process than JSON.

!!! abstract "References"

    - [UBJSON Website](http://ubjson.org)

## Serialization

The library uses the following mapping from JSON values types to UBJSON types according to the UBJSON specification:

| JSON value type | value/range                               | UBJSON type    | marker |
|-----------------|-------------------------------------------|----------------|--------|
| null            | `null`                                    | null           | `Z`    |
| boolean         | `true`                                    | true           | `T`    |
| boolean         | `false`                                   | false          | `F`    |
| number_integer  | -9223372036854775808..-2147483649         | int64          | `L`    |
| number_integer  | -2147483648..-32769                       | int32          | `l`    |
| number_integer  | -32768..-129                              | int16          | `I`    |
| number_integer  | -128..127                                 | int8           | `i`    |
| number_integer  | 128..255                                  | uint8          | `U`    |
| number_integer  | 256..32767                                | int16          | `I`    |
| number_integer  | 32768..2147483647                         | int32          | `l`    |
| number_integer  | 2147483648..9223372036854775807           | int64          | `L`    |
| number_unsigned | 0..127                                    | int8           | `i`    |
| number_unsigned | 128..255                                  | uint8          | `U`    |
| number_unsigned | 256..32767                                | int16          | `I`    |
| number_unsigned | 32768..2147483647                         | int32          | `l`    |
| number_unsigned | 2147483648..9223372036854775807           | int64          | `L`    |
| number_unsigned | 9223372036854775808..18446744073709551615 | high-precision | `H`    |
| number_float    | *any value*                               | float64        | `D`    |
| string          | *with shortest length indicator*          | string         | `S`    |
| array           | *see notes on optimized format*           | array          | `[`    |
| object          | *see notes on optimized format*           | map            | `{`    |

!!! success "Complete mapping"

    The mapping is **complete** in the sense that any JSON value type can be converted to a UBJSON value.

    Any UBJSON output created by `to_ubjson` can be successfully parsed by `from_ubjson`.

!!! warning "Size constraints"

    The following values can **not** be converted to a UBJSON value:

      - strings with more than 9223372036854775807 bytes (theoretical)

!!! warning "UTF-8 validation of string values and object keys"

    UBJSON's required string encoding is UTF-8. By default (the [`error_handler`](../../api/basic_json/to_ubjson.md)
    parameter left at `keep`), `to_ubjson()` writes the bytes of string values and object keys unchanged, even if they
    are not valid UTF-8. With `error_handler_t::strict`, it throws
    [`type_error.316`](../../home/exceptions.md#jsonexceptiontype_error316) for ill-formed UTF-8 instead;
    `replace`/`ignore` sanitize the string. [`JSON_STRICT_BINARY_UTF8`](../../api/macros/json_strict_binary_utf8.md)
    makes `strict` the default.

!!! info "Unused UBJSON markers"

    The following markers are not used in the conversion:
    
    - `Z`: no-op values are not created.
    - `C`: single-byte strings are serialized with `S` markers.

!!! info "NaN/infinity handling"

    If NaN or Infinity are stored inside a JSON number, they are serialized properly. This behavior differs from the
    [`dump()`](../../api/basic_json/dump.md) function which serializes NaN or Infinity to `null`.

!!! info "Optimized formats"

    The optimized formats for containers are supported: Parameter `use_size` adds size information to the beginning of a
    container and removes the closing marker. Parameter `use_type` further checks whether all elements of a container
    have the same type and adds the type marker to the beginning of the container. The `use_type` parameter must only be
    used together with `use_size = true`.

    Note that `use_size = true` alone may result in larger representations - the benefit of this parameter is that the
    receiving side is immediately informed on the number of elements of the container.

    An array whose type marker is `Z` (null), `T` (true) or `F` (false) stores no payload at all, because the marker
    already is the value. Its declared count is therefore the only thing that decides how much memory the receiving side
    allocates, and a handful of bytes can describe billions of elements. `from_ubjson` rejects such an array with
    [`out_of_range.408`](../../home/exceptions.md#jsonexceptionout_of_range408) when the count exceeds 1,048,576
    (`1 << 20`), and `to_ubjson` writes longer arrays of these types without the annotation, so any value it produces
    can be read back.

!!! info "Binary values"

    If the JSON data contains the binary type, the value stored is a list of integers, as suggested by the UBJSON
    documentation.  In particular, this means that serialization and the deserialization of a JSON containing binary
    values into UBJSON and back will result in a different JSON object.

??? example "Example: serialize JSON values to UBJSON, with and without size/type optimization"

    ```cpp
    --8<-- "examples/to_ubjson.cpp"
    ```

    Output:

    ```c
    --8<-- "examples/to_ubjson.output"
    ```





### Byte layout

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

`to_ubjson` encodes it to 51 bytes (shown in hexadecimal; the encoding contains no whitespace). The colors mark the role of each byte: <span class="bl bl-t">type/marker</span> <span class="bl bl-l">length/count/size</span> <span class="bl bl-d">data</span>.

<div class="byte-layout" markdown="0"><table>
<thead><tr><th>JSON</th><th>Bytes</th><th>Meaning</th></tr></thead><tbody>
<tr><td><code>{</code></td><td><span class="bl bl-t">7B</span></td><td>object start (<code>{</code>)</td></tr>
<tr><td><code>&quot;id&quot;: 300,</code></td><td><span class="bl bl-l">69 02</span> <span class="bl bl-d">69 64</span> <span class="bl bl-t">49</span> <span class="bl bl-d">01 2C</span></td><td>key: length 2 as int8 (<code>i</code>), then UTF-8 bytes; value: int16 (<code>I</code>), big-endian</td></tr>
<tr><td><code>&quot;name&quot;: &quot;json&quot;,</code></td><td><span class="bl bl-l">69 04</span> <span class="bl bl-d">6E 61 6D 65</span> <span class="bl bl-t">53</span> <span class="bl bl-l">69 04</span> <span class="bl bl-d">6A 73 6F 6E</span></td><td>key: length 4; value: string (<code>S</code>), length 4 as int8, UTF-8 bytes</td></tr>
<tr><td><code>&quot;pi&quot;: 3.14,</code></td><td><span class="bl bl-l">69 02</span> <span class="bl bl-d">70 69</span> <span class="bl bl-t">44</span> <span class="bl bl-d">40 09 1E B8 51 EB 85 1F</span></td><td>key: length 2; value: float64 (<code>D</code>), big-endian</td></tr>
<tr><td><code>&quot;tags&quot;: [</code></td><td><span class="bl bl-l">69 04</span> <span class="bl bl-d">74 61 67 73</span> <span class="bl bl-t">5B</span></td><td>key: length 4; value: array start (<code>[</code>)</td></tr>
<tr><td><code>&quot;a&quot;,</code></td><td><span class="bl bl-t">53</span> <span class="bl bl-l">69 01</span> <span class="bl bl-d">61</span></td><td>string, length 1</td></tr>
<tr><td><code>&quot;b&quot;</code></td><td><span class="bl bl-t">53</span> <span class="bl bl-l">69 01</span> <span class="bl bl-d">62</span></td><td>string, length 1</td></tr>
<tr><td><code>]</code></td><td><span class="bl bl-t">5D</span></td><td>array end (<code>]</code>)</td></tr>
<tr><td><code>}</code></td><td><span class="bl bl-t">7D</span></td><td>object end (<code>}</code>)</td></tr>
</tbody></table></div>

## Deserialization

The library maps UBJSON types to JSON value types as follows:

| UBJSON type | JSON value type                         | marker |
|-------------|-----------------------------------------|--------|
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

!!! success "Complete mapping"

    The mapping is **complete** in the sense that any UBJSON value can be converted to a JSON value.

!!! warning "Ill-formed UTF-8 in string values and object keys"

    UBJSON's required string encoding is UTF-8, but checking it on read is opt-in: with the
    [`error_handler`](../../api/basic_json/from_ubjson.md) parameter left at `keep` (the default), `from_ubjson()`
    accepts a string value or object key whose bytes are not valid UTF-8 and hands them back unchanged. Passing
    `error_handler_t::strict` makes `from_ubjson()` check and throw
    [`parse_error.113`](../../home/exceptions.md#jsonexceptionparse_error113) for ill-formed UTF-8, and
    `replace`/`ignore` sanitize the string instead of keeping it. However,
    [`dump()`](../../api/basic_json/dump.md) still requires valid UTF-8 and throws
    [`type_error.316`](../../home/exceptions.md#jsonexceptiontype_error316) for a value read with the default
    `keep` handler, unless an error handler is passed that replaces or ignores the ill-formed bytes. `to_ubjson()`'s
    own `error_handler` parameter defaults to `keep` (see above), so such a value is written back unchanged.

??? example "Example: deserialize a JSON value from UBJSON"

    ```cpp
    --8<-- "examples/from_ubjson.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/from_ubjson.output"
    ```
