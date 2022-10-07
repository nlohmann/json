# <small>nlohmann::</small>ordered_json

```cpp
using ordered_json = basic_json<ordered_map>;
```

This type preserves the insertion order of object keys.

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
