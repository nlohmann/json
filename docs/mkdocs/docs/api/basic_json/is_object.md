# <small>nlohmann::basic_json::</small>is_object

```cpp
constexpr bool is_object() const noexcept;
```

This function returns `#!cpp true` if and only if the JSON value is an object.
    
## Return value

`#!cpp true` if type is an object, `#!cpp false` otherwise.

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Examples

??? example

    The following code exemplifies `is_object()` for all JSON types.
    
    ```cpp
    --8<-- "examples/is_object.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/is_object.output"
    ```

## Version history

- Added in version 1.0.0.
