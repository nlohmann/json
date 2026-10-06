# <small>nlohmann::basic_json::</small>is_array

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

## Examples

??? example

    The following code exemplifies `is_array()` for all JSON types.
    
    ```cpp
    --8<-- "examples/is_array.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/is_array.output"
    ```

## See also

- [is_object](is_object.md) checks whether the JSON value is an object
- [is_structured](is_structured.md) checks whether the JSON value is structured (array or object)
- [type](type.md) returns the type of the JSON value
- [array_t](array_t.md) the type used to store JSON arrays
- [basic_json_view::is_array](../basic_json_view/is_array.md) - the same check on a zero-copy view

## Version history

- Added in version 1.0.0.
