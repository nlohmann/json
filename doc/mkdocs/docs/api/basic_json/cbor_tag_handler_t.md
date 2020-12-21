# basic_json::cbor_tag_handler_t

```cpp
enum class cbor_tag_handler_t
{
    error,
    ignore
};
```

This enumeration is used in the [`from_cbor`](from_cbor.md) function to choose how to treat tags:

error
:   throw a `parse_error` exception in case of a tag

ignore
:   ignore tags

## Version history

- Added in version 3.9.0.
