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

The exact mapping and its limitations is described on a [dedicated page](../../features/binary_formats/bson.md).

## Parameters

`j` (in)
:   JSON value to serialize

`o` (in)
:   output adapter to write serialization to

## Return value

1. BSON serialization as byte vector
2. /

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

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

## Version history

- Added in version 3.4.0.
