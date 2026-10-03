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

## See also

- [is_primitive](is_primitive.md) checks whether the JSON value is primitive
- [type](type.md) returns the type of the JSON value
- [string_t](string_t.md) the type used to store JSON strings

## Version history

- Added in version 1.0.0.
