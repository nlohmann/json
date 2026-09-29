# <small>nlohmann::</small>json

```cpp
using json = basic_json<>;
```

This type is the default specialization of the [basic_json](basic_json/index.md) class which uses the standard template
types.

## Examples

??? example

    The example below demonstrates how to use the type `nlohmann::json`.

    ```cpp
    --8<-- "examples/README.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/README.output"
    ```

## See also

- [basic_json](basic_json/index.md) - the underlying class template
- [ordered_json](ordered_json.md) - specialization that preserves the insertion order of object keys

## Version history

Since version 1.0.0.
