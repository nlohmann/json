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

      - strings with more than 18446744073709551615 bytes, i.e., $2^{64}-1$ bytes (theoretical)

!!! info "Unused BJData markers"

    The following markers are not used in the conversion:

    - `Z`: no-op values are not created.
    - `C`: single-byte strings are serialized with `S` markers.

!!! info "NaN/infinity handling"

    If NaN or Infinity are stored inside a JSON number, they are serialized properly. This behavior differs from the
    `dump()` function which serializes NaN or Infinity to `#!json null`.

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

    Likewise, when a JSON object in the above form is serialzed using
    [`to_bjdata`](../../api/basic_json/to_bjdata.md), it is automatically converted into a compact BJData ND-array. The
    only exception is, that when the 1-dimensional vector stored in `"_ArraySize_"` contains a single integer or two
    integers with one being 1, a regular 1-D optimized array is generated.

    The current version of this library does not yet support automatic detection of and conversion from a nested JSON
    array input to a BJData ND-array.

    [JDataAAFmt]: https://github.com/NeuroJSON/jdata/blob/master/JData_specification.md#annotated-storage-of-n-d-arrays)

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

    [BJDataBinArr]: https://github.com/NeuroJSON/bjdata/blob/master/Binary_JData_Specification.md#optimized-binary-array)

??? example

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

??? example

    ```cpp
    --8<-- "examples/from_bjdata.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/from_bjdata.output"
    ```
