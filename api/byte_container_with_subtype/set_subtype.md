# <small>nlohmann::byte_container_with_subtype::</small>set_subtype

```cpp
void set_subtype(subtype_type subtype) noexcept;
```

Sets the binary subtype of the value, also flags a binary JSON value as having a subtype, which has implications for
serialization.

## Parameters

`subtype` (in)
:   subtype to set

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Examples

??? example

    The example below demonstrates how a subtype can be set with `set_subtype`.

    ```cpp
    --8<-- "examples/byte_container_with_subtype__set_subtype.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/byte_container_with_subtype__set_subtype.output"
    ```

## Version history

Since version 3.8.0.
