# basic_json::is_boolean

```cpp
constexpr bool is_boolean() const noexcept;
```

This function returns `#!cpp true` if and only if the JSON value is `#!json true` or `#!json false`.
    
## Return value

`#!cpp true` if type is boolean, `#!cpp false` otherwise.

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Example

??? example

    The following code exemplifies `is_boolean()` for all JSON types.
    
    ```cpp
    --8<-- "examples/is_boolean.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/is_boolean.output"
    ```

## Version history

- Added in version 1.0.0.
