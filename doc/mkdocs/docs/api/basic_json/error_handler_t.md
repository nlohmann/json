# basic_json::error_handler_t

```cpp
enum class error_handler_t {
    strict,
    replace,
    ignore
};
```

This enumeration is used in the [`dump`](dump.md) function to choose how to treat decoding errors while serializing a
`basic_json` value. Three values are differentiated:

strict
:   throw a `type_error` exception in case of invalid UTF-8

replace
:   replace invalid UTF-8 sequences with U+FFFD (� REPLACEMENT CHARACTER)

ignore
:   ignore invalid UTF-8 sequences; all bytes are copied to the output unchanged

## Version history

- Added in version 3.4.0.
