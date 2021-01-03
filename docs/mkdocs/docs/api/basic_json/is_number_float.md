# <small>nlohmann::basic_json::</small>is_number_float

```cpp
constexpr bool is_number_float() const noexcept;
```

This function returns `#!cpp true` if and only if the JSON value is a floating-point number. This excludes signed and
unsigned integer values.
    
## Return value

`#!cpp true` if type is a floating-point number, `#!cpp false` otherwise.

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Examples

??? example

    The following code exemplifies `is_number_float()` for all JSON types.
    
    ```cpp
    --8<-- "examples/is_number_float.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/is_number_float.output"
    ```

## See also

- [is_number()](is_number.md) check if value is a number
- [is_number_integer()](is_number_integer.md) check if value is an integer or unsigned integer number
- [is_number_unsigned()](is_number_unsigned.md) check if value is an unsigned integer number

## Version history

- Added in version 1.0.0.
