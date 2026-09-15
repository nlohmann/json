# <small>nlohmann::byte_container_with_subtype::</small>operator==

```cpp
bool operator==(const byte_container_with_subtype& rhs) const;
```

Compares two `byte_container_with_subtype` values for equality by comparing the underlying binary
container, the subtype, and whether a subtype is set.

## Parameters

`rhs` (in)
:   value to compare `*this` against

## Return value

whether `*this` and `rhs` are equal

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Linear in the size of the underlying binary container.

## Examples

??? example

    The example demonstrates comparing `byte_container_with_subtype` values.

    ```cpp
    --8<-- "examples/byte_container_with_subtype__operator_eq.cpp"
    ```

    Output:

    ```
    --8<-- "examples/byte_container_with_subtype__operator_eq.output"
    ```

## Version history

- Since version 3.8.0.
