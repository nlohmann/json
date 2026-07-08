# <small>nlohmann::basic_json::</small>to_bson

```cpp
// (1)
static std::vector<std::uint8_t> to_bson(const basic_json& j);

// (2)
static void to_bson(const basic_json& j, detail::output_adapter<std::uint8_t> o);
static void to_bson(const basic_json& j, detail::output_adapter<char> o);
```

BSON (Binary JSON) is a binary format in which zero or more ordered key/value pairs are stored as a single entity (a
so-called document).

1. Returns a byte vector containing the BSON serialization.
2. Writes the BSON serialization to an output adapter.

The exact mapping and its limitations are described on a [dedicated page](../../features/binary_formats/bson.md).

## Parameters

`j` (in)
:   JSON value to serialize

`o` (in)
:   output adapter to write serialization to

## Return value

1. BSON serialization as a byte vector
2. (none)

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

- Throws [`type_error.317`](../../home/exceptions.md#jsonexceptiontype_error317) if the top-level type of the JSON value
  is not an object; example: `"to serialize to BSON, top-level type must be object, but is string"`
- Throws [`out_of_range.409`](../../home/exceptions.md#jsonexceptionout_of_range409) if a key in the JSON object contains
  a null byte (code point U+0000); example: `"BSON key cannot contain code point U+0000 (at byte 2)"`

## Complexity

Linear in the size of the JSON value `j`.

## Examples

??? example

    The example shows the serialization of a JSON value to a byte vector in BSON format.
     
    ```cpp
    --8<-- "examples/to_bson.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/to_bson.output"
    ```

## See also

- [from_bson](from_bson.md) create a JSON value from an input in BSON format
- [to_cbor](to_cbor.md) create a CBOR serialization of a JSON value
- [to_msgpack](to_msgpack.md) create a MessagePack serialization of a JSON value
- [to_ubjson](to_ubjson.md) create a UBJSON serialization of a JSON value
- [to_bjdata](to_bjdata.md) create a BJData serialization of a JSON value

## Version history

- Added in version 3.4.0.
