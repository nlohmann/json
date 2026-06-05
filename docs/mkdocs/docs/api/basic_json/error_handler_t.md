# <small>nlohmann::basic_json::</small>error_handler_t

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
