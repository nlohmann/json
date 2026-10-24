# <small>nlohmann::byte_container_with_subtype::</small>container_type

```cpp
using container_type = BinaryType;
```

The type of the underlying binary container, forwarded from the `BinaryType` template parameter that
`byte_container_with_subtype` is instantiated with. `byte_container_with_subtype` publicly inherits from
`container_type`.

See [`basic_json::binary_t`](../basic_json/binary_t.md) for the type typically used to instantiate
`BinaryType`.

## Examples

??? example

    The example shows the type `container_type`.

    ```cpp
    --8<-- "examples/byte_container_with_subtype__container_type.cpp"
    ```

    Output:

    ```
    --8<-- "examples/byte_container_with_subtype__container_type.output"
    ```

## Version history

- Since version 3.8.0.
