# <small>nlohmann::byte_container_with_subtype::</small>operator!=

```cpp
bool operator!=(const byte_container_with_subtype& rhs) const;
```

Compares two byte containers for inequality. Returns `#!cpp !(rhs == *this)`; see [`operator==`](operator_eq.md) for
the equality semantics.

## Parameters

`rhs` (in)
:   byte container to compare `*this` with

## Return value

whether `*this` and `rhs` are not equal

## Complexity

Linear in the size of the compared containers.

## Examples

??? example

    The example below demonstrates comparing byte containers with and without subtypes.

    ```cpp
    --8<-- "examples/byte_container_with_subtype__operator__notequal.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/byte_container_with_subtype__operator__notequal.output"
    ```

## See also

- [operator==](operator_eq.md) comparison: equal
- [has_subtype](has_subtype.md) return whether the value has a subtype
- [subtype](subtype.md) return the binary subtype

## Version history

- Added in version 3.8.0.
