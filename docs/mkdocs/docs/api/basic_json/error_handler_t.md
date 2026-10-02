# <small>nlohmann::basic_json::</small>error_handler_t

```cpp
enum class error_handler_t {
    strict,
    replace,
    ignore,
    keep
};
```

This enumeration is used in the [`dump`](dump.md) function to choose how to treat decoding errors while serializing a
`basic_json` value. Four values are differentiated:

strict
:   throw a `type_error` exception in case of invalid UTF-8

replace
:   replace invalid UTF-8 sequences with U+FFFD (� REPLACEMENT CHARACTER)

ignore
:   ignore invalid UTF-8 sequences; all valid bytes are copied to the output unchanged, and invalid bytes are dropped

keep
:   keep invalid UTF-8 sequences; all bytes are copied to the output unchanged. Valid characters are still escaped as
    usual (e.g., `"`, `\\`, and control characters), so the result has valid JSON syntax, but it is not valid UTF-8.
    In particular, [`parse`](parse.md) rejects it, and with `ensure_ascii` set to `true`, the invalid bytes are the
    only non-ASCII bytes of the output.

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

## Version history

- Added in version 3.4.0.
- Added value `keep` in version 3.13.0.
