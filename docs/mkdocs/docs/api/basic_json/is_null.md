# <small>nlohmann::basic_json::</small>is_null

```cpp
constexpr bool is_null() const noexcept;
```

This function returns `#!cpp true` if and only if the JSON value is `#!json null`.
    
## Return value

`#!cpp true` if type is `#!json null`, `#!cpp false` otherwise.

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Examples

??? example

    The following code exemplifies `is_null()` for all JSON types.
    
    ```cpp
    --8<-- "examples/is_null.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/is_null.output"
    ```

## Version history

- Added in version 1.0.0.
