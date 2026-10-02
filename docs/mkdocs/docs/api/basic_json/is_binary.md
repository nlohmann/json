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

## See also

- [is_primitive](is_primitive.md) checks whether the JSON value is primitive
- [binary_t](binary_t.md) the type used to store binary values
- [get_binary](get_binary.md) returns a reference to the stored binary value
- [basic_json_view::is_binary](../basic_json_view/is_binary.md) - the same check on a zero-copy view

## Version history

- Added in version 3.8.0.
