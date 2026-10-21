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

## See also

- [is_array](is_array.md) checks whether the JSON value is an array
- [is_structured](is_structured.md) checks whether the JSON value is structured (array or object)
- [type](type.md) returns the type of the JSON value
- [object_t](object_t.md) the type used to store JSON objects
- [basic_json_view::is_object](../basic_json_view/is_object.md) - the same check on a zero-copy view

## Version history

- Added in version 1.0.0.
