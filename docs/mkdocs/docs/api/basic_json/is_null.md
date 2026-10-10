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

## See also

- [is_array](is_array.md) checks whether the JSON value is an array
- [is_object](is_object.md) checks whether the JSON value is an object
- [type](type.md) returns the type of the JSON value
- [value_t](value_t.md) the enumeration of JSON types
- [basic_json_view::is_null](../basic_json_view/is_null.md) - the same check on a zero-copy view

## Version history

- Added in version 1.0.0.
