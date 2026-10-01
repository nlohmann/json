# <small>nlohmann::basic_json::</small>to_bjdata

```cpp
// (1)
static std::vector<std::uint8_t> to_bjdata(const basic_json& j,
                                           const bool use_size = false,
                                           const bool use_type = false,
                                           const bjdata_version_t version = bjdata_version_t::draft2,
                                           const error_handler_t error_handler = error_handler_t::strict);

// (2)
static void to_bjdata(const basic_json& j, detail::output_adapter<std::uint8_t> o,
                      const bool use_size = false, const bool use_type = false,
                      const bjdata_version_t version = bjdata_version_t::draft2,
                      const error_handler_t error_handler = error_handler_t::strict);
static void to_bjdata(const basic_json& j, detail::output_adapter<char> o,
                      const bool use_size = false, const bool use_type = false,
                      const bjdata_version_t version = bjdata_version_t::draft2,
                      const error_handler_t error_handler = error_handler_t::strict);
```

Serializes a given JSON value `j` to a byte vector using the BJData (Binary JData) serialization format. BJData aims to
be more compact than JSON itself, yet more efficient to parse.

1. Returns a byte vector containing the BJData serialization.
2. Writes the BJData serialization to an output adapter.

The exact mapping and its limitations are described on a [dedicated page](../../features/binary_formats/bjdata.md).

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

`error_handler` (in)
:   how to treat a string or object key in `j` that is not valid UTF-8; see [`error_handler_t`](error_handler_t.md).
    The default, `strict`, throws; `keep` writes the ill-formed bytes to the output as is, as every version of
    `to_bjdata` did before this parameter was added; `replace`/`ignore` sanitize it the same way
    [`dump`](dump.md) would

## Return value

1. BJData serialization as byte vector
2. (none)

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

- Throws [`other_error.502`](../../home/exceptions.md#jsonexceptionother_error502) if `use_type` is true and `use_size`
  is false.
- Throws [type_error.316](../../home/exceptions.md#jsonexceptiontype_error316) if a string or object key in `j` is
  not valid UTF-8 and `error_handler` is `strict` (the default)

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

## See also

- [from_bjdata](from_bjdata.md) create a JSON value from an input in BJData format
- [to_cbor](to_cbor.md) create a CBOR serialization of a JSON value
- [to_msgpack](to_msgpack.md) create a MessagePack serialization of a JSON value
- [to_bson](to_bson.md) create a BSON serialization of a JSON value
- [to_ubjson](to_ubjson.md) create a UBJSON serialization of a JSON value
- [to_bon8](to_bon8.md) create a BON8 serialization of a JSON value

## Version history

- Added in version 3.11.0.
- BJData version parameter (for draft3 binary encoding) added in version 3.12.0.
- Throwing `type_error.316` for a string or object key that is not valid UTF-8 added in version 3.13.0.
- Added `error_handler` parameter in version 3.13.0.