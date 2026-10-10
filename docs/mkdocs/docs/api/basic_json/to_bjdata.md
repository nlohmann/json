# <small>nlohmann::basic_json::</small>to_bjdata

```cpp
// (1)
static std::vector<std::uint8_t> to_bjdata(const basic_json& j,
                                           const bool use_size = false,
                                           const bool use_type = false,
                                           const bjdata_version_t version = bjdata_version_t::draft2,
                                           const error_handler_t error_handler = error_handler_t::keep);

// (2)
static void to_bjdata(const basic_json& j, detail::output_adapter<std::uint8_t> o,
                      const bool use_size = false, const bool use_type = false,
                      const bjdata_version_t version = bjdata_version_t::draft2,
                      const error_handler_t error_handler = error_handler_t::keep);
static void to_bjdata(const basic_json& j, detail::output_adapter<char> o,
                      const bool use_size = false, const bool use_type = false,
                      const bjdata_version_t version = bjdata_version_t::draft2,
                      const error_handler_t error_handler = error_handler_t::keep);
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
    The default, `keep`, writes the ill-formed bytes to the output as is, as every version of `to_bjdata` did before
    this parameter was added; `strict` throws; `replace`/`ignore` sanitize it the same way [`dump`](dump.md) would.
    If [`JSON_STRICT_BINARY_UTF8`](../macros/json_strict_binary_utf8.md) is enabled, the default is `strict` instead.

## Return value

1. BJData serialization as byte vector
2. (none)

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

- Throws [`other_error.502`](../../home/exceptions.md#jsonexceptionother_error502) if `use_type` is true and `use_size`
  is false, and `j` contains a non-empty array, object, or binary value.
- Throws [type_error.316](../../home/exceptions.md#jsonexceptiontype_error316) if a string or object key in `j` is
  not valid UTF-8 and `error_handler` is `strict` (the default only if
  [`JSON_STRICT_BINARY_UTF8`](../macros/json_strict_binary_utf8.md) is enabled)
- Throws [type_error.321](../../home/exceptions.md#jsonexceptiontype_error321) if `j` or a value nested in it is
  discarded; example: `"cannot serialize discarded value to BJData"`

## Complexity

Linear in the size of the JSON value `j`.

## Examples

??? example "Example: serialize a JSON value to BJData"

    The example shows the serialization of a JSON value to a byte vector in BJData format.
     
    ```cpp
    --8<-- "examples/to_bjdata.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/to_bjdata.output"
    ```

??? example "Example: other_error.502 exception"

    The example shows how requesting type annotations (`use_type`) without size annotations (`use_size`) throws an
    exception, because type-optimized containers can only be read back with a preceding size.

    ```cpp
    --8<-- "examples/to_bjdata__exception.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/to_bjdata__exception.output"
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
- Added `error_handler` parameter in version 3.13.0. Its default, `keep`, writes the bytes of a string or object key
  that is not valid UTF-8 unchanged, as before; `strict` (the default if
  [`JSON_STRICT_BINARY_UTF8`](../macros/json_strict_binary_utf8.md) is enabled) throws `type_error.316`.
- Throws `type_error.321` for a discarded value since version 3.13.0; previously, a discarded value nested in an
  array or object was silently skipped, producing invalid BJData.