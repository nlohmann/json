# <small>nlohmann::basic_json::</small>to_msgpack

```cpp
// (1)
static std::vector<std::uint8_t> to_msgpack(const basic_json& j,
                                            const error_handler_t error_handler = error_handler_t::keep);

// (2)
static void to_msgpack(const basic_json& j, detail::output_adapter<std::uint8_t> o,
                       const error_handler_t error_handler = error_handler_t::keep);
static void to_msgpack(const basic_json& j, detail::output_adapter<char> o,
                       const error_handler_t error_handler = error_handler_t::keep);
```

Serializes a given JSON value `j` to a byte vector using the MessagePack serialization format. MessagePack is a binary
serialization format that aims to be more compact than JSON itself, yet more efficient to parse.

1. Returns a byte vector containing the MessagePack serialization.
2. Writes the MessagePack serialization to an output adapter.

The exact mapping and its limitations are described on a [dedicated page](../../features/binary_formats/messagepack.md).

## Parameters

`j` (in)
:   JSON value to serialize

`o` (in)
:   output adapter to write serialization to

`error_handler` (in)
:   how to treat a string or object key in `j` that is not valid UTF-8; see [`error_handler_t`](error_handler_t.md).
    The default, `keep`, writes the ill-formed bytes to the output as is, as every version of `to_msgpack` did before
    this parameter was added and as the MessagePack specification allows; `strict` throws; `replace`/`ignore` sanitize
    it the same way [`dump`](dump.md) would. Unlike the other binary writers, the default stays `keep` even if
    [`JSON_STRICT_BINARY_UTF8`](../macros/json_strict_binary_utf8.md) is enabled.

## Return value

1. MessagePack serialization as a byte vector
2. (none)

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

- Throws [`out_of_range.412`](../../home/exceptions.md#jsonexceptionout_of_range412) if the length of a string, binary
  value, array, or object exceeds 4294967295, the maximum MessagePack can store; example:
  `"MessagePack length 4294967296 exceeds maximum of 4294967295"`
- Throws [`out_of_range.415`](../../home/exceptions.md#jsonexceptionout_of_range415) if the subtype of a binary value
  exceeds 255, the maximum of the MessagePack ext type; example:
  `"subtype 70000 is too large for the MessagePack ext type (max 255)"`
- Throws [type_error.316](../../home/exceptions.md#jsonexceptiontype_error316) if a string or object key in `j` is
  not valid UTF-8 and `error_handler` is `strict`
- Throws [type_error.321](../../home/exceptions.md#jsonexceptiontype_error321) if `j` or a value nested in it is
  discarded; example: `"cannot serialize discarded value to MessagePack"`

## Complexity

Linear in the size of the JSON value `j`.

## Examples

??? example "Example: serialize a JSON value to MessagePack"

    The example shows the serialization of a JSON value to a byte vector in MessagePack format.
     
    ```cpp
    --8<-- "examples/to_msgpack.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/to_msgpack.output"
    ```

??? example "Example: out_of_range.415 exception"

    The example shows how serializing a binary value whose subtype exceeds 255 throws an exception, because the
    MessagePack ext type stores the subtype in a single byte.

    ```cpp
    --8<-- "examples/to_msgpack__exception.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/to_msgpack__exception.output"
    ```

## See also

- [from_msgpack](from_msgpack.md) create a JSON value from an input in MessagePack format
- [to_cbor](to_cbor.md) create a CBOR serialization of a JSON value
- [to_bson](to_bson.md) create a BSON serialization of a JSON value
- [to_ubjson](to_ubjson.md) create a UBJSON serialization of a JSON value
- [to_bjdata](to_bjdata.md) create a BJData serialization of a JSON value
- [to_bon8](to_bon8.md) create a BON8 serialization of a JSON value

## Version history

- Added in version 2.0.9.
- Throws `out_of_range.412` and `out_of_range.415` since version 3.13.0.
- Added `error_handler` parameter in version 3.13.0. Its default, `keep`, writes the bytes of a string or object key
  that is not valid UTF-8 unchanged, as before.
- Fixed in version 3.13.0 to serialize `number_integer_t`/`number_unsigned_t` pairs of different width correctly;
  before, integers could be serialized with the wrong value if `number_integer_t` was narrower than
  `number_unsigned_t`.
- Throws `type_error.321` for a discarded value since version 3.13.0; previously, a discarded value nested in an
  array or object was silently skipped, producing invalid MessagePack.
