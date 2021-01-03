# <small>nlohmann::basic_json::</small>is_string

```cpp
constexpr bool is_string() const noexcept;
```

This function returns `#!cpp true` if and only if the JSON value is a string.
    
## Return value

`#!cpp true` if type is a string, `#!cpp false` otherwise.

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Examples

??? example

    The following code exemplifies `is_string()` for all JSON types.
    
    ```cpp
    --8<-- "examples/is_string.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/is_string.output"
    ```

## Version history

- Added in version 1.0.0.
