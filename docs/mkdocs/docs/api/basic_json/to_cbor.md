# <small>nlohmann::basic_json::</small>to_cbor

```cpp
// (1)
static std::vector<std::uint8_t> to_cbor(const basic_json& j);

// (2)
static void to_cbor(const basic_json& j, detail::output_adapter<std::uint8_t> o);
static void to_cbor(const basic_json& j, detail::output_adapter<char> o);
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

## Return value

1. CBOR serialization as a byte vector
2. (none)

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

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

## Version history

- Added in version 2.0.9.
- Compact representation of floating-point numbers added in version 3.8.0.
