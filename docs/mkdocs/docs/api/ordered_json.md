# <small>nlohmann::</small>ordered_json

```cpp
using ordered_json = basic_json<ordered_map>;
```

This type preserves the insertion order of object keys.

## Iterator invalidation

The type is based on [`ordered_map`](ordered_map.md) which in turn uses a `std::vector` to store object elements.
Therefore, adding object elements can yield a reallocation in which case all iterators (including the
[`end()`](basic_json/end.md) iterator) and all references to the elements are invalidated. Also, any iterator or
reference after the insertion point will point to the same index, which is now a different value.

## Complexity

[`ordered_map`](ordered_map.md) has no lookup index: every key-based object operation is a linear scan, so building or
parsing an object of `n` keys costs O(n²) rather than O(n log n). See
[`ordered_map` complexity](ordered_map.md#complexity) for the per-operation table and for measured numbers.

## Examples

??? example

    The example below demonstrates how `ordered_json` preserves the insertion order of object keys.

    ```cpp
    --8<-- "examples/ordered_json.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/ordered_json.output"
    ```

## See also

- [ordered_map](ordered_map.md)
- [Object Order](../features/object_order.md)

## Version history

Since version 3.9.0.
