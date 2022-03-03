# <small>nlohmann::basic_json::</small>to_ubjson

```cpp
// (1)
static std::vector<std::uint8_t> to_ubjson(const basic_json& j,
                                           const bool use_size = false,
                                           const bool use_type = false);

// (2)
static void to_ubjson(const basic_json& j, detail::output_adapter<std::uint8_t> o,
                      const bool use_size = false, const bool use_type = false);
static void to_ubjson(const basic_json& j, detail::output_adapter<char> o,
                      const bool use_size = false, const bool use_type = false);
```

Serializes a given JSON value `j` to a byte vector using the UBJSON (Universal Binary JSON) serialization format. UBJSON
aims to be more compact than JSON itself, yet more efficient to parse.

1. Returns a byte vector containing the UBJSON serialization.
2. Writes the UBJSON serialization to an output adapter.

The exact mapping and its limitations is described on a [dedicated page](../../features/binary_formats/ubjson.md).

## Parameters

`j` (in)
:   JSON value to serialize

`o` (in)
:   output adapter to write serialization to

`use_size` (in)
:   whether to add size annotations to container types; optional, `#!cpp false` by default.

`use_type` (in)
:   whether to add type annotations to container types (must be combined with `#!cpp use_size = true`); optional,
    `#!cpp false` by default.

## Return value

1. UBJSON serialization as byte vector
2. (none)

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Complexity

Linear in the size of the JSON value `j`.

## Examples

??? example

    The example shows the serialization of a JSON value to a byte vector in UBJSON format.
     
    ```cpp
    --8<-- "examples/to_ubjson.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/to_ubjson.output"
    ```

## Version history

- Added in version 3.1.0.
