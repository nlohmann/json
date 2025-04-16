# <small>nlohmann::basic_json::</small>is_number_unsigned

```cpp
constexpr bool is_number_unsigned() const noexcept;
```

This function returns `#!cpp true` if and only if the JSON value is an unsigned integer number. This excludes
floating-point and signed integer values.
    
## Return value

`#!cpp true` if type is an unsigned integer number, `#!cpp false` otherwise.

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Examples

??? example

    The following code exemplifies `is_number_unsigned()` for all JSON types.
    
    ```cpp
    --8<-- "examples/is_number_unsigned.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/is_number_unsigned.output"
    ```

## See also

- [is_number()](is_number.md) check if the value is a number
- [is_number_integer()](is_number_integer.md) check if the value is an integer or unsigned integer number
- [is_number_float()](is_number_float.md) check if the value is a floating-point number

## Version history

- Added in version 2.0.0.
