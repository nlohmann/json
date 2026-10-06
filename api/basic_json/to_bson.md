# <small>nlohmann::basic_json::</small>to_bson

```cpp
// (1)
static std::vector<std::uint8_t> to_bson(const basic_json& j,
                                         const error_handler_t error_handler = error_handler_t::keep);

// (2)
static void to_bson(const basic_json& j, detail::output_adapter<std::uint8_t> o,
                    const error_handler_t error_handler = error_handler_t::keep);
static void to_bson(const basic_json& j, detail::output_adapter<char> o,
                    const error_handler_t error_handler = error_handler_t::keep);
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

`error_handler` (in)
:   how to treat a string or object key in `j` that is not valid UTF-8; see [`error_handler_t`](error_handler_t.md).
    The default, `keep`, writes the ill-formed bytes to the output as is, as every version of `to_bson` did before
    this parameter was added; `strict` throws; `replace`/`ignore` sanitize it the same way [`dump`](dump.md) would.
    If [`JSON_STRICT_BINARY_UTF8`](../macros/json_strict_binary_utf8.md) is enabled, the default is `strict` instead.

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
- Throws [`out_of_range.412`](../../home/exceptions.md#jsonexceptionout_of_range412) if the length of a document, array,
  string, or binary value exceeds the range of the 32-bit BSON length field; example:
  `"BSON length 2147483661 exceeds maximum of 2147483647"`
- Throws [`out_of_range.415`](../../home/exceptions.md#jsonexceptionout_of_range415) if the subtype of a binary value
  exceeds 255, the maximum of the BSON binary subtype; example:
  `"subtype 70000 is too large for the BSON binary subtype (max 255)"`
- Throws [type_error.316](../../home/exceptions.md#jsonexceptiontype_error316) if a string or object key is
  not valid UTF-8 and `error_handler` is `strict` (the default only if
  [`JSON_STRICT_BINARY_UTF8`](../macros/json_strict_binary_utf8.md) is enabled)
- Throws [type_error.321](../../home/exceptions.md#jsonexceptiontype_error321) if a value nested in `j` is discarded
  (the top-level value itself is covered by `type_error.317` above, since it must be an object); example:
  `"cannot serialize discarded value to BSON"`

## Complexity

Linear in the size of the JSON value `j`. The length prefixes of all nested documents and arrays are computed in one
pass before anything is written.

## Examples

??? example "Example: serialize a JSON value to BSON"

    The example shows the serialization of a JSON value to a byte vector in BSON format.
     
    ```cpp
    --8<-- "examples/to_bson.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/to_bson.output"
    ```

??? example "Example: out_of_range.409 exception"

    The example shows how serializing a JSON object whose key contains a null byte (U+0000) throws an exception, because
    BSON keys are null-terminated C strings and cannot contain U+0000 themselves.

    ```cpp
    --8<-- "examples/to_bson__exception.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/to_bson__exception.output"
    ```

## See also

- [from_bson](from_bson.md) create a JSON value from an input in BSON format
- [to_cbor](to_cbor.md) create a CBOR serialization of a JSON value
- [to_msgpack](to_msgpack.md) create a MessagePack serialization of a JSON value
- [to_ubjson](to_ubjson.md) create a UBJSON serialization of a JSON value
- [to_bjdata](to_bjdata.md) create a BJData serialization of a JSON value
- [to_bon8](to_bon8.md) create a BON8 serialization of a JSON value

## Version history

- Added in version 3.4.0.
- Throws `out_of_range.412` and `out_of_range.415` since version 3.13.0.
- Linear in the size of `j`, and no longer limited by the call stack for deeply nested values, since version 3.13.0.
- `out_of_range.415` is now detected before anything is written, like the other exceptions above, since version 3.13.0.
- Throws `type_error.321` for a discarded value nested in `j` since version 3.13.0; previously, it was silently
  skipped, producing a document whose declared size did not match what was actually written.
- Added `error_handler` parameter in version 3.13.0. Its default, `keep`, writes the bytes of a string or object key
  that is not valid UTF-8 unchanged, as before; `strict` (the default if
  [`JSON_STRICT_BINARY_UTF8`](../macros/json_strict_binary_utf8.md) is enabled) throws `type_error.316` before anything
  is written.
