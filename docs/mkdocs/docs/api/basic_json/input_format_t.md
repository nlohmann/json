# <small>nlohmann::basic_json::</small>input_format_t

```cpp
enum class input_format_t {
    json,
    cbor,
    msgpack,
    ubjson,
    bson,
    bjdata
};
```

This enumeration is used in the [`sax_parse`](sax_parse.md) function to choose the input format to parse:

json
:   JSON (JavaScript Object Notation)

cbor
:   CBOR (Concise Binary Object Representation)

msgpack
:   MessagePack

ubjson
:   UBJSON (Universal Binary JSON)

bson
:   BSON (Binary JSON)

bjdata
:   BJData (Binary JData)

## Examples

??? example

    The example below shows how an `input_format_t` enum value is passed to `sax_parse` to set the input format to CBOR.

    ```cpp
    --8<-- "examples/sax_parse__binary.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/sax_parse__binary.output"
    ```

## Version history

- Added in version 3.2.0.
