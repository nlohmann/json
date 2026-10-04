# <small>nlohmann::byte_container_with_subtype::</small>operator==

```cpp
bool operator==(const byte_container_with_subtype& rhs) const;
```

Compares two byte containers for equality by comparing (1) the underlying binary data (the `BinaryType` base, compared
with `BinaryType`'s own `operator==`) and (2) the subtype information -- both containers must either have no subtype,
or have a subtype and the same subtype value.

## Parameters

`rhs` (in)
:   byte container to compare `*this` with

## Return value

whether `*this` and `rhs` are equal

## Complexity

Linear in the size of the compared containers.

## Examples

??? example

    The example below demonstrates comparing byte containers with and without subtypes.

    ```cpp
    --8<-- "examples/byte_container_with_subtype__operator__equal.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/byte_container_with_subtype__operator__equal.output"
    ```

## See also

- [operator!=](operator_ne.md) comparison: not equal
- [has_subtype](has_subtype.md) return whether the value has a subtype
- [subtype](subtype.md) return the binary subtype

## Version history

- Added in version 3.8.0.
