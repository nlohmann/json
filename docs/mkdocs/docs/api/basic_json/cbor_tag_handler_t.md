# <small>nlohmann::basic_json::</small>cbor_tag_handler_t

```cpp
enum class cbor_tag_handler_t
{
    error,
    ignore,
    store
};
```

This enumeration is used in the [`from_cbor`](from_cbor.md) function to choose how to treat tags:

error
:   throw a `parse_error` exception in case of a tag

ignore
:   ignore tags

store
:   store tagged values as binary container with subtype (for bytes 0xd8..0xdb)

## Examples

??? example

    The example below shows how the different values of the `cbor_tag_handler_t` influence the behavior of
    [`from_cbor`](from_cbor.md) when reading a tagged byte string.

    ```cpp
    --8<-- "examples/cbor_tag_handler_t.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/cbor_tag_handler_t.output"
    ```

## Version history

- Added in version 3.9.0. Added value `store` in 3.10.0.
