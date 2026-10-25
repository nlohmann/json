# BJData

The [BJData format](https://neurojson.org) was derived from and improved upon
[Universal Binary JSON(UBJSON)](https://ubjson.org) specification (Draft 12). Specifically, it introduces an optimized
array container for efficient storage of N-dimensional packed arrays (**ND-arrays**); it also adds 5 new type markers -
`[u] - uint16`, `[m] - uint32`, `[M] - uint64`, `[h] - float16` and `[B] - byte` - to unambiguously map common binary
numeric types; furthermore, it uses little-endian (LE) to store all numerics instead of big-endian (BE) as in UBJSON to
avoid unnecessary conversions on commonly available platforms.

Compared to other binary JSON-like formats such as MessagePack and CBOR, both BJData and UBJSON demonstrate a rare
combination of being both binary and **quasi-human-readable**. This is because all semantic elements in BJData and
UBJSON, including the data-type markers and name/string types, are directly human-readable. Data stored in the
BJData/UBJSON format is not only compact in size, fast to read/write, but also can be directly searched or read using
simple processing.

!!! abstract "References"

    - [BJData Specification](https://neurojson.org/bjdata/draft2)

## Byte layout

BJData follows the structure of UBJSON: a one-byte, human-readable ASCII *type marker* followed by the payload of that type, with strings prefixed by a length that is itself an integer value. In contrast to UBJSON, numbers are stored in little-endian byte order, and additional markers cover unsigned 16/32/64-bit integers, half-precision floats, and bytes. Containers can be written unoptimized (opened with `[` or `{`, closed with `]` or `}`) or optimized with a declared element type (`$`) and/or count (`#`). BJData extends the optimized form: the count can be a list of dimensions, which stores an N-dimensional packed array as a flat sequence of values without any per-element markers.

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

`to_bjdata` encodes it to 51 bytes (shown in hexadecimal; the encoding contains no whitespace). The colors mark the role of each byte: <span class="bl bl-t">type/marker</span> <span class="bl bl-l">length/count/size</span> <span class="bl bl-d">data</span>.

<div class="byte-layout" markdown="0"><table>
<thead><tr><th>JSON</th><th>Bytes</th><th>Meaning</th></tr></thead><tbody>
<tr><td><code>{</code></td><td><span class="bl bl-t">7B</span></td><td>object start (<code>{</code>)</td></tr>
<tr><td><code>&quot;id&quot;: 300,</code></td><td><span class="bl bl-l">69 02</span> <span class="bl bl-d">69 64</span> <span class="bl bl-t">49</span> <span class="bl bl-d">2C 01</span></td><td>key: length 2 as int8 (<code>i</code>), then UTF-8 bytes; value: int16 (<code>I</code>), little-endian</td></tr>
<tr><td><code>&quot;name&quot;: &quot;json&quot;,</code></td><td><span class="bl bl-l">69 04</span> <span class="bl bl-d">6E 61 6D 65</span> <span class="bl bl-t">53</span> <span class="bl bl-l">69 04</span> <span class="bl bl-d">6A 73 6F 6E</span></td><td>key: length 4; value: string (<code>S</code>), length 4 as int8, UTF-8 bytes</td></tr>
<tr><td><code>&quot;pi&quot;: 3.14,</code></td><td><span class="bl bl-l">69 02</span> <span class="bl bl-d">70 69</span> <span class="bl bl-t">44</span> <span class="bl bl-d">1F 85 EB 51 B8 1E 09 40</span></td><td>key: length 2; value: float64 (<code>D</code>), little-endian</td></tr>
<tr><td><code>&quot;tags&quot;: [</code></td><td><span class="bl bl-l">69 04</span> <span class="bl bl-d">74 61 67 73</span> <span class="bl bl-t">5B</span></td><td>key: length 4; value: array start (<code>[</code>)</td></tr>
<tr><td><code>&quot;a&quot;,</code></td><td><span class="bl bl-t">53</span> <span class="bl bl-l">69 01</span> <span class="bl bl-d">61</span></td><td>string, length 1</td></tr>
<tr><td><code>&quot;b&quot;</code></td><td><span class="bl bl-t">53</span> <span class="bl bl-l">69 01</span> <span class="bl bl-d">62</span></td><td>string, length 1</td></tr>
<tr><td><code>]</code></td><td><span class="bl bl-t">5D</span></td><td>array end (<code>]</code>)</td></tr>
<tr><td><code>}</code></td><td><span class="bl bl-t">7D</span></td><td>object end (<code>}</code>)</td></tr>
</tbody></table></div>

## Serialization

The library uses the following mapping from JSON values types to BJData types according to the BJData specification:

| JSON value type | value/range                               | BJData type    | marker |
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
| number_integer  | 32768..65535                              | uint16         | `u`    |
| number_integer  | 65536..2147483647                         | int32          | `l`    |
| number_integer  | 2147483648..4294967295                    | uint32         | `m`    |
| number_integer  | 4294967296..9223372036854775807           | int64          | `L`    |
| number_integer  | 9223372036854775808..18446744073709551615 | uint64         | `M`    |
| number_unsigned | 0..127                                    | int8           | `i`    |
| number_unsigned | 128..255                                  | uint8          | `U`    |
| number_unsigned | 256..32767                                | int16          | `I`    |
| number_unsigned | 32768..65535                              | uint16         | `u`    |
| number_unsigned | 65536..2147483647                         | int32          | `l`    |
| number_unsigned | 2147483648..4294967295                    | uint32         | `m`    |
| number_unsigned | 4294967296..9223372036854775807           | int64          | `L`    |
| number_unsigned | 9223372036854775808..18446744073709551615 | uint64         | `M`    |
| number_float    | *any value*                               | float64        | `D`    |
| string          | *with shortest length indicator*          | string         | `S`    |
| array           | *see notes on optimized format/ND-array*  | array          | `[`    |
| object          | *see notes on optimized format*           | map            | `{`    |
| binary          | *see notes on binary values*              | array          | `[$B`  |

!!! success "Complete mapping"

    The mapping is **complete** in the sense that any JSON value type can be converted to a BJData value.

    Any BJData output created by `to_bjdata` can be successfully parsed by `from_bjdata`.

!!! warning "Size constraints"

    The following values can **not** be converted to a BJData value:

      - strings with more than 18446744073709551615 bytes, i.e., 2<sup>64</sup>-1 bytes (theoretical)

!!! warning "UTF-8 validation of string values and object keys"

    BJData strings must use UTF-8 encoding. By default (the [`error_handler`](../../api/basic_json/to_bjdata.md)
    parameter left at `keep`), `to_bjdata()` writes the bytes of string values and object keys unchanged, even if they
    are not valid UTF-8. With `error_handler_t::strict`, it throws
    [`type_error.316`](../../home/exceptions.md#jsonexceptiontype_error316) for ill-formed UTF-8 instead;
    `replace`/`ignore` sanitize the string. [`JSON_STRICT_BINARY_UTF8`](../../api/macros/json_strict_binary_utf8.md)
    makes `strict` the default.

!!! info "Unused BJData markers"

    The following markers are not used in the conversion:

    - `Z`: no-op values are not created.
    - `C`: single-byte strings are serialized with `S` markers.

!!! info "NaN/infinity handling"

    If NaN or Infinity are stored inside a JSON number, they are serialized properly. This behavior differs from the
    [`dump()`](../../api/basic_json/dump.md) function which serializes NaN or Infinity to `#!json null`.

!!! info "Endianness"

    A breaking difference between BJData and UBJSON is the endianness of numerical values. In BJData, all numerical data
    types (integers `UiuImlML` and floating-point values `hdD`) are stored in the little-endian (LE) byte order as
    opposed to big-endian as used by UBJSON. Adopting LE to store numeric records avoids unnecessary byte swapping on
    most modern computers where LE is used as the default byte order.

!!! info "Optimized formats"

    Optimized formats for containers are supported via two parameters of
    [`to_bjdata`](../../api/basic_json/to_bjdata.md):

    - Parameter `use_size` adds size information to the beginning of a container and removes the closing marker.
    - Parameter `use_type` further checks whether all elements of a container have the same type and adds the type
      marker to the beginning of the container. The `use_type` parameter must only be used together with
      `use_size = true`.

    Note that `use_size = true` alone may result in larger representations - the benefit of this parameter is that the
    receiving side is immediately informed of the number of elements in the container.

!!! info "ND-array optimized format"

    BJData extends UBJSON's optimized array **size** marker to support ND-arrays of uniform numerical data types
    (referred to as *packed arrays*). For example, the 2-D `uint8` integer array `[[1,2],[3,4],[5,6]]`, stored as nested
    optimized array in UBJSON `[ [$U#i2 1 2 [$U#i2 3 4 [$U#i2 5 6 ]`, can be further compressed in BJData to
    `[$U#[$i#i2 2 3 1 2 3 4 5 6` or `[$U#[i2 i3] 1 2 3 4 5 6`.

    To maintain type and size information, ND-arrays are converted to JSON objects following the **annotated array
    format** (defined in the [JData specification (Draft 3)][JDataAAFmt]), when parsed using
    [`from_bjdata`](../../api/basic_json/from_bjdata.md). For example, the above 2-D `uint8` array can be parsed and
    accessed as

    ```json
    {
        "_ArrayType_": "uint8",
        "_ArraySize_": [2,3],
        "_ArrayData_": [1,2,3,4,5,6]
    }
    ```

    Likewise, when a JSON object in the above form is serialized using
    [`to_bjdata`](../../api/basic_json/to_bjdata.md), it is automatically converted into a compact BJData ND-array.

    When parsing, an ND-array whose dimension vector is empty, contains a single integer, contains two integers with the
    first being 1, or contains a 0 is returned as a regular (possibly empty) array rather than an annotated object.

    An object is only converted if the annotation describes a packed array that is parsed back into the same annotated
    object; otherwise it is serialized as a regular JSON object, so the annotation is never lost in a round trip. This requires
    all of the following:

    - `"_ArrayType_"` is one of `uint8`, `int8`, `uint16`, `int16`, `uint32`, `int32`, `uint64`, `int64`, `single`,
      `double`, `char`, or `byte`,
    - `"_ArraySize_"` is an array, since the dimensions are written as the ND-array header's length,
    - `"_ArraySize_"` has at least two entries and is not a 1×N row vector (first entry 1), since other shapes are
      parsed back as a regular array,
    - every entry of `"_ArraySize_"` is a positive integer, and their product is representable as a `std::size_t`,
    - `"_ArrayData_"` is an array holding exactly that many elements, and
    - every element of `"_ArrayData_"` is a number of the kind named by `"_ArrayType_"`: for the integer types, a
      value that fits the named width; for `double`, any value; for `single`, a value that survives narrowing to
      `float` and back without change (for instance, `0.1` does not, since it is not exactly representable as
      `float`).

    An annotated object is always read back with its keys in the order shown above, `"_ArrayType_"`, `"_ArraySize_"`,
    `"_ArrayData_"`, regardless of the order the ND-array's header stores them in on the wire. This matters for
    `ordered_json`, whose comparison takes key order into account.

    The current version of this library does not yet support automatic detection of and conversion from a nested JSON
    array input to a BJData ND-array.

    [JDataAAFmt]: https://github.com/NeuroJSON/jdata/blob/master/JData_specification.md#annotated-storage-of-n-d-arrays

!!! info "Restrictions in optimized data types for arrays and objects"

    Due to diminished space saving, hampered readability, and increased security risks, in BJData, the allowed data
    types following the `$` marker in an optimized array and object container are restricted to
    **non-zero-fixed-length** data types. Therefore, the valid optimized type markers can only be one of
    `UiuImlMLhdDCB`. This also means other variable (`[{SH`) or zero-length types (`TFN`) can not be used in an
    optimized array or object in BJData.

!!! info "Binary values"

    BJData provides a dedicated `B` marker (defined in the [BJData specification (Draft 3)][BJDataBinArr]) that is used
    in optimized arrays to designate binary data. This means that, unlike UBJSON, binary data can be both serialized and
    deserialized.

    To preserve compatibility with BJData Draft 2, the Draft 3 optimized binary array must be explicitly enabled using
    the `version` parameter of [`to_bjdata`](../../api/basic_json/to_bjdata.md).

    In Draft2 mode (default), if the JSON data contains the binary type, the value stored as a list of integers, as
    suggested by the BJData documentation. In particular, this means that the serialization and the deserialization of
    JSON containing binary values into BJData and back will result in a different JSON object.

    [BJDataBinArr]: https://github.com/NeuroJSON/bjdata/blob/master/Binary_JData_Specification.md#optimized-binary-array

??? example "Example: serialize JSON values to BJData, with and without size/type optimization"

    ```cpp
    --8<-- "examples/to_bjdata.cpp"
    ```

    Output:

    ```c
    --8<-- "examples/to_bjdata.output"
    ```

## Deserialization

The library maps BJData types to JSON value types as follows:

| BJData type | JSON value type                          | marker   |
|-------------|------------------------------------------|----------|
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

!!! success "Complete mapping"

    The mapping is **complete** in the sense that any BJData value can be converted to a JSON value.

!!! warning "Ill-formed UTF-8 in string values and object keys"

    BJData strings must use UTF-8 encoding, but checking it on read is opt-in: with the
    [`error_handler`](../../api/basic_json/from_bjdata.md) parameter left at `keep` (the default), `from_bjdata()`
    accepts a string value or object key whose bytes are not valid UTF-8 and hands them back unchanged. Passing
    `error_handler_t::strict` makes `from_bjdata()` check and throw
    [`parse_error.113`](../../home/exceptions.md#jsonexceptionparse_error113) for ill-formed UTF-8, and
    `replace`/`ignore` sanitize the string instead of keeping it. However,
    [`dump()`](../../api/basic_json/dump.md) still requires valid UTF-8 and throws
    [`type_error.316`](../../home/exceptions.md#jsonexceptiontype_error316) for a value read with the default
    `keep` handler, unless an error handler is passed that replaces or ignores the ill-formed bytes. `to_bjdata()`'s
    own `error_handler` parameter defaults to `keep` (see above), so such a value is written back unchanged.

!!! info "Round trips"

    A value returned by [`from_bjdata`](../../api/basic_json/from_bjdata.md) can be serialized with
    [`to_bjdata`](../../api/basic_json/to_bjdata.md) using any combination of options and parsed back into an equal
    value, and serializing that value again with the same options produces the same bytes. The exception is binary
    values: they are only written as an optimized binary array (`[$B`) if Draft 3 is enabled and both `use_size` and
    `use_type` are set. Otherwise, they are written as arrays of integers and parsed back as such (see the notes on
    binary values above), and serializing such an array again may choose different, but equally valid, type markers.
    The bytes can then differ, but parsing them again yields the same value.

??? example "Example: deserialize a JSON value from BJData"

    ```cpp
    --8<-- "examples/from_bjdata.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/from_bjdata.output"
    ```
