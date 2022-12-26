# <small>nlohmann::basic_json::</small>as_base_class

```cpp
json_base_class_t& as_base_class();
const json_base_class_t& as_base_class() const;
```

Returns this object casted to [json_base_class_t](json_base_class_t.md).

## Return value

This object casted to [json_base_class_t](json_base_class_t.md).

## Examples

??? example

    Use `as_base_class` to access shadowed methods and member variables defined in [json_base_class_t](json_base_class_t.md).
    
    ```cpp
    --8<-- "examples/as_base_class.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/as_base_class.output"
    ```

## Version history

Added in version ???.???.???
