# <small>nlohmann::basic_json::</small>to_bjdata

```cpp
// (1)
static std::vector<std::uint8_t> to_bjdata(const basic_json& j,
                                           const bool use_size = false,
                                           const bool use_type = false,
                                           const bjdata_version_t version = bjdata_version_t::draft2);

// (2)
static void to_bjdata(const basic_json& j, detail::output_adapter<std::uint8_t> o,
                      const bool use_size = false, const bool use_type = false,
                      const bjdata_version_t version = bjdata_version_t::draft2);
static void to_bjdata(const basic_json& j, detail::output_adapter<char> o,
                      const bool use_size = false, const bool use_type = false,
                      const bjdata_version_t version = bjdata_version_t::draft2);
```

Serializes a given JSON value `j` to a byte vector using the BJData (Binary JData) serialization format. BJData aims to
be more compact than JSON itself, yet more efficient to parse.

1. Returns a byte vector containing the BJData serialization.
2. Writes the BJData serialization to an output adapter.

The exact mapping and its limitations is described on a [dedicated page](../../features/binary_formats/bjdata.md).

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

`version` (in)
:   which version of BJData to use (see note on "Binary values" on [BJData](../../features/binary_formats/bjdata.md));
optional, `#!cpp bjdata_version_t::draft2` by default.

## Return value

1. BJData serialization as byte vector
2. (none)

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Complexity

Linear in the size of the JSON value `j`.

## Examples

??? example

    The example shows the serialization of a JSON value to a byte vector in BJData format.
     
    ```cpp
    --8<-- "examples/to_bjdata.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/to_bjdata.output"
    ```

## Version history

- Added in version 3.11.0.
- BJData version parameter (for draft3 binary encoding) added in version 3.12.0.