# <small>nlohmann::basic_json::</small>to_cbor

```cpp
// (1)
static std::vector<std::uint8_t> to_cbor(const basic_json& j,
                                          const error_handler_t error_handler = error_handler_t::strict);

// (2)
static void to_cbor(const basic_json& j, detail::output_adapter<std::uint8_t> o,
                     const error_handler_t error_handler = error_handler_t::strict);
static void to_cbor(const basic_json& j, detail::output_adapter<char> o,
                     const error_handler_t error_handler = error_handler_t::strict);
```

Serializes a given JSON value `j` to a byte vector using the CBOR (Concise Binary Object Representation) serialization
format. CBOR is a binary serialization format that aims to be more compact than JSON itself, yet more efficient to
parse.

1. Returns a byte vector containing the CBOR serialization.
2. Writes the CBOR serialization to an output adapter.

The exact mapping and its limitations are described on a [dedicated page](../../features/binary_formats/cbor.md).

## Parameters

`j` (in)
:   JSON value to serialize

`o` (in)
:   output adapter to write serialization to

`error_handler` (in)
:   how to treat a string or object key in `j` that is not valid UTF-8; see [`error_handler_t`](error_handler_t.md).
    The default, `strict`, throws; `keep` writes the ill-formed bytes to the output as is, as every version of
    `to_cbor` did before this parameter was added; `replace`/`ignore` sanitize it the same way
    [`dump`](dump.md) would

## Return value

1. CBOR serialization as a byte vector
2. (none)

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

- Throws [type_error.316](../../home/exceptions.md#jsonexceptiontype_error316) if a string or object key in `j` is
  not valid UTF-8 and `error_handler` is `strict` (the default)

## Complexity

Linear in the size of the JSON value `j`.

## Examples

??? example

    The example shows the serialization of a JSON value to a byte vector in CBOR format.
     
    ```cpp
    --8<-- "examples/to_cbor.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/to_cbor.output"
    ```

## See also

- [from_cbor](from_cbor.md) create a JSON value from an input in CBOR format
- [to_msgpack](to_msgpack.md) create a MessagePack serialization of a JSON value
- [to_bson](to_bson.md) create a BSON serialization of a JSON value
- [to_ubjson](to_ubjson.md) create a UBJSON serialization of a JSON value
- [to_bjdata](to_bjdata.md) create a BJData serialization of a JSON value
- [to_bon8](to_bon8.md) create a BON8 serialization of a JSON value

## Version history

- Added in version 2.0.9.
- Compact representation of floating-point numbers added in version 3.8.0.
- Throwing `type_error.316` for a string or object key that is not valid UTF-8 added in version 3.13.0.
- Added `error_handler` parameter in version 3.13.0.
