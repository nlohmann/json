# <small>nlohmann::basic_json::</small>is_binary

```cpp
constexpr bool is_binary() const noexcept;
```

This function returns `#!cpp true` if and only if the JSON value is a binary array.
    
## Return value

`#!cpp true` if type is binary, `#!cpp false` otherwise.

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Examples

??? example

    The following code exemplifies `is_binary()` for all JSON types.
    
    ```cpp
    --8<-- "examples/is_binary.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/is_binary.output"
    ```

## Version history

- Added in version 3.8.0.
