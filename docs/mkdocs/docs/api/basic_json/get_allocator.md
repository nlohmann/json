# <small>nlohmann::basic_json::</small>get_allocator

```cpp
static allocator_type get_allocator();
```

Returns the allocator associated with the container.
    
## Return value

associated allocator

## Examples

??? example

    The example shows how `get_allocator()` is used to created `json` values.
    
    ```cpp
    --8<-- "examples/get_allocator.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/get_allocator.output"
    ```

## Version history

- Added in version 1.0.0.
