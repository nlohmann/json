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

## Version history

- Added in version 3.9.0. Added value `store` in 3.10.0.
