# UBJSON

Universal Binary JSON (UBJSON) is a binary form directly imitating JSON, but requiring fewer bytes of data. It aims to achieve the generality of JSON, combined with being much easier to process than JSON.

!!! abstract "References"

	- [UBJSON Website](http://ubjson.org)

## Serialization

The library uses the following mapping from JSON values types to UBJSON types according to the UBJSON specification:

JSON value type | value/range                       | UBJSON type | marker
--------------- | --------------------------------- | ----------- | ------
null            | `null`                            | null        | `Z`
boolean         | `true`                            | true        | `T`
boolean         | `false`                           | false       | `F`
number_integer  | -9223372036854775808..-2147483649 | int64       | `L`
number_integer  | -2147483648..-32769               | int32       | `l`
number_integer  | -32768..-129                      | int16       | `I`
number_integer  | -128..127                         | int8        | `i`
number_integer  | 128..255                          | uint8       | `U`
number_integer  | 256..32767                        | int16       | `I`
number_integer  | 32768..2147483647                 | int32       | `l`
number_integer  | 2147483648..9223372036854775807   | int64       | `L`
number_unsigned | 0..127                            | int8        | `i`
number_unsigned | 128..255                          | uint8       | `U`
number_unsigned | 256..32767                        | int16       | `I`
number_unsigned | 32768..2147483647                 | int32       | `l`
number_unsigned | 2147483648..9223372036854775807   | int64       | `L`
number_unsigned | 2147483649..18446744073709551615  | high-precision | `H`
number_float    | *any value*                       | float64     | `D`
string          | *with shortest length indicator*  | string      | `S`
array           | *see notes on optimized format*   | array       | `[`
object          | *see notes on optimized format*   | map         | `{`

!!! success "Complete mapping"

	The mapping is **complete** in the sense that any JSON value type can be converted to a UBJSON value.

	Any UBJSON output created by `to_ubjson` can be successfully parsed by `from_ubjson`.

!!! warning "Size constraints"

	The following values can **not** be converted to a UBJSON value:

      - strings with more than 9223372036854775807 bytes (theoretical)

!!! info "Unused UBJSON markers"

	The following markers are not used in the conversion:
    
    - `Z`: no-op values are not created.
    - `C`: single-byte strings are serialized with `S` markers.

!!! info "NaN/infinity handling"

	If NaN or Infinity are stored inside a JSON number, they are
    serialized properly. This behavior differs from the `dump()`
    function which serializes NaN or Infinity to `null`.

!!! info "Optimized formats"

	The optimized formats for containers are supported: Parameter
    `use_size` adds size information to the beginning of a container and
    removes the closing marker. Parameter `use_type` further checks
    whether all elements of a container have the same type and adds the
    type marker to the beginning of the container. The `use_type`
    parameter must only be used together with `use_size = true`.

    Note that `use_size = true` alone may result in larger representations -
    the benefit of this parameter is that the receiving side is
    immediately informed on the number of elements of the container.

!!! info "Binary values"

	If the JSON data contains the binary type, the value stored is a list
    of integers, as suggested by the UBJSON documentation.  In particular,
    this means that serialization and the deserialization of a JSON
    containing binary values into UBJSON and back will result in a
    different JSON object.


??? example

    ```cpp
    --8<-- "examples/to_ubjson.cpp"
    ```

    Output:

    ```c
    --8<-- "examples/to_ubjson.output"
    ```

## Deserialization

The library maps UBJSON types to JSON value types as follows:

UBJSON type | JSON value type                         | marker
----------- | --------------------------------------- | ------
no-op       | *no value, next value is read*          | `N`
null        | `null`                                  | `Z`
false       | `false`                                 | `F`
true        | `true`                                  | `T`
float32     | number_float                            | `d`
float64     | number_float                            | `D`
uint8       | number_unsigned                         | `U`
int8        | number_integer                          | `i`
int16       | number_integer                          | `I`
int32       | number_integer                          | `l`
int64       | number_integer                          | `L`
string      | string                                  | `S`
char        | string                                  | `C`
array       | array (optimized values are supported)  | `[`
object      | object (optimized values are supported) | `{`

!!! success "Complete mapping"

	The mapping is **complete** in the sense that any UBJSON value can be converted to a JSON value.


??? example

    ```cpp
    --8<-- "examples/from_ubjson.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/from_ubjson.output"
    ```
