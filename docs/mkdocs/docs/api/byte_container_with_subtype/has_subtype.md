# <small>nlohmann::byte_container_with_subtype::</small>has_subtype

```cpp
constexpr bool has_subtype() const noexcept;
```

Returns whether the value has a subtype.

## Return value

whether the value has a subtype

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Examples

??? example

    The example below demonstrates how `has_subtype` can check whether a subtype was set.

    ```cpp
    --8<-- "examples/byte_container_with_subtype__has_subtype.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/byte_container_with_subtype__has_subtype.output"
    ```

## Version history

Since version 3.8.0.
