# <small>nlohmann::basic_json::</small>error_handler_t

```cpp
enum class error_handler_t {
    strict,
    replace,
    ignore,
    keep
};
```

This enumeration is used to choose how to treat ill-formed UTF-8 in a string value or object key:

- [`dump`](dump.md) uses it while serializing a `basic_json` value to text.
- [`to_cbor`](to_cbor.md), [`to_msgpack`](to_msgpack.md), [`to_ubjson`](to_ubjson.md), [`to_bjdata`](to_bjdata.md),
  and [`to_bson`](to_bson.md) use it while serializing a `basic_json` value to that binary format. Their default is
  `keep`, as no binary writer checked before this parameter was added. CBOR, UBJSON, BJData, and BSON require valid
  UTF-8, so for these four the default is `strict` if [`JSON_STRICT_BINARY_UTF8`](../macros/json_strict_binary_utf8.md)
  is enabled; MessagePack's specification explicitly allows a string to contain ill-formed UTF-8, so `to_msgpack`
  stays at `keep`. `to_bon8` does not take this parameter: BON8 always validates, since UTF-8 lead bytes are
  structural to that format.
- [`from_cbor`](from_cbor.md), [`from_msgpack`](from_msgpack.md), [`from_ubjson`](from_ubjson.md),
  [`from_bjdata`](from_bjdata.md), and [`from_bson`](from_bson.md) use it while parsing that binary format, to decide
  whether to check a string value or object key for well-formed UTF-8 at all; by default (`keep`) they do not, as no
  binary reader did before this parameter was added. `from_bon8` does not take this parameter, for the same reason
  `to_bon8` does not.

Four values are differentiated:

strict
:   throw a `type_error`/`parse_error` exception in case of invalid UTF-8

replace
:   replace invalid UTF-8 sequences with U+FFFD (� REPLACEMENT CHARACTER)

ignore
:   ignore invalid UTF-8 sequences; all valid bytes are copied to the output unchanged, and invalid bytes are dropped

keep
:   keep invalid UTF-8 sequences unchanged; only meaningful for the binary formats mentioned above, since [`dump`]
    (dump.md) itself must produce text, and `keep` there writes the ill-formed bytes to the output as is, so the
    result is then not valid UTF-8 (but still equals the input bytes exactly, including around any well-formed
    characters, which are still escaped as usual)

## Examples

??? example

    The example below shows how the different values of the `error_handler_t` influence the behavior of
    [`dump`](dump.md) when reading serializing an invalid UTF-8 sequence.

    ```cpp
    --8<-- "examples/error_handler_t.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/error_handler_t.output"
    ```

## See also

- [dump](dump.md) serializes a JSON value, with an `error_handler_t` parameter to configure invalid UTF-8 handling
- [Handling invalid UTF-8](../../features/serialization.md#handling-invalid-utf-8) - the article on handling invalid UTF-8

## Version history

- Added in version 3.4.0.
- Added `keep`, and made this enumeration apply to the binary readers and writers in addition to `dump`, in version
  3.13.0.
