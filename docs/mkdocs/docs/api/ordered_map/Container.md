# <small>nlohmann::ordered_map::</small>Container

```cpp
using Container = std::vector<std::pair<const Key, T>, Allocator>;
```

The base container type that `ordered_map` publicly inherits from. Elements are stored in insertion
order as `#!cpp std::pair<const Key, T>` entries in a `std::vector`.

## Examples

??? example

    The example shows the type `Container`.

    ```cpp
    --8<-- "examples/ordered_map__Container.cpp"
    ```

    Output:

    ```
    --8<-- "examples/ordered_map__Container.output"
    ```

## Version history

- Added in version 3.9.0 to implement [`nlohmann::ordered_json`](../ordered_json.md).
