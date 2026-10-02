# <small>nlohmann::byte_container_with_subtype::</small>clear_subtype

```cpp
void clear_subtype() noexcept;
```

Clears the binary subtype and flags the value as not having a subtype, which has implications for serialization; for
instance, MessagePack will prefer the bin family over the ext family.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Examples

??? example

    The example below demonstrates how `clear_subtype` can remove subtypes.

    ```cpp
    --8<-- "examples/byte_container_with_subtype__clear_subtype.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/byte_container_with_subtype__clear_subtype.output"
    ```

## See also

- [set_subtype](set_subtype.md) sets the binary subtype
- [has_subtype](has_subtype.md) return whether the value has a subtype
- [subtype](subtype.md) return the binary subtype

## Version history

Since version 3.8.0.
