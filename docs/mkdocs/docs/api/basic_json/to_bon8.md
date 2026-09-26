# <small>nlohmann::basic_json::</small>to_bon8

```cpp
// (1)
static std::vector<std::uint8_t> to_bon8(const basic_json& j);

// (2)
static void to_bon8(const basic_json& j, detail::output_adapter<std::uint8_t> o);
static void to_bon8(const basic_json& j, detail::output_adapter<char> o);
```

Serializes a given JSON value `j` to a byte vector using the BON8 (Binary Object Notation 8) serialization format. BON8
is a compact binary serialization format that stores strings as UTF-8 without a length prefix.

1. Returns a byte vector containing the BON8 serialization.
2. Writes the BON8 serialization to an output adapter.

The exact mapping and its limitations are described on a [dedicated page](../../features/binary_formats/bon8.md).

## Parameters

`j` (in)
:   JSON value to serialize

`o` (in)
:   output adapter to write serialization to

## Return value

1. BON8 serialization as a byte vector
2. (none)

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value `j`, which is never modified.
With (2), the bytes written before the exception remain in the output adapter.

## Exceptions

- Throws [out_of_range.407](../../home/exceptions.md#jsonexceptionout_of_range407) if `j` contains an unsigned integer
  above 9223372036854775807, which BON8 cannot represent
- Throws [type_error.316](../../home/exceptions.md#jsonexceptiontype_error316) if `j` contains a string that is not
  valid UTF-8

## Complexity

Linear in the size of the JSON value `j`.

## Examples

??? example

    The example shows the serialization of a JSON value to a byte vector in BON8 format.
     
    ```cpp
    --8<-- "examples/to_bon8.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/to_bon8.output"
    ```

## See also

- [from_bon8](from_bon8.md) create a JSON value from an input in BON8 format
- [to_cbor](to_cbor.md) create a CBOR serialization of a JSON value
- [to_msgpack](to_msgpack.md) create a MessagePack serialization of a JSON value
- [to_bson](to_bson.md) create a BSON serialization of a JSON value
- [to_ubjson](to_ubjson.md) create a UBJSON serialization of a JSON value
- [to_bjdata](to_bjdata.md) create a BJData serialization of a JSON value

## Version history

- Added in version 3.13.0.
