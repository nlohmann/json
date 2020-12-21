# basic_json::is_array

```cpp
constexpr bool is_array() const noexcept;
```

This function returns `#!cpp true` if and only if the JSON value is an array.
    
## Return value

`#!cpp true` if type is an array, `#!cpp false` otherwise.

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Example

??? example

    The following code exemplifies `is_array()` for all JSON types.
    
    ```cpp
    --8<-- "examples/is_array.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/is_array.output"
    ```

## Version history

- Added in version 1.0.0.
