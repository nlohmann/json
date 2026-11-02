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

- [`basic_json`](basic_json/index.md) - the underlying class template
- [`ordered_json`](ordered_json.md) - specialization that preserves the insertion order of object keys
- [Types](../features/types/index.md) - the JSON value types and how they are stored
- [Converting values](../features/conversions.md) - get values out of a JSON value and put values in
- [Creating JSON values](../features/creating_values.md) - all the ways to build a JSON value

## Version history

Added in version 1.0.0.
