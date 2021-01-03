# <small>nlohmann::basic_json::</small>is_number

```cpp
constexpr bool is_number() const noexcept;
```

This function returns `#!cpp true` if and only if the JSON value is a number. This includes both integer (signed and
unsigned) and floating-point values.
    
## Return value

`#!cpp true` if type is number (regardless whether integer, unsigned integer or floating-type), `#!cpp false` otherwise.

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Possible implementation

```cpp
constexpr bool is_number() const noexcept
{
    return is_number_integer() || is_number_float();
}
```

## Examples

??? example

    The following code exemplifies `is_number()` for all JSON types.
    
    ```cpp
    --8<-- "examples/is_number.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/is_number.output"
    ```

## See also

- [is_number_integer()](is_number_integer.md) check if value is an integer or unsigned integer number
- [is_number_unsigned()](is_number_unsigned.md) check if value is an unsigned integer number
- [is_number_float()](is_number_float.md) check if value is a floating-point number

## Version history

- Added in version 1.0.0.
- Extended to also return `#!cpp true` for unsigned integers in 2.0.0.
