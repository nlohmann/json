# basic_json::is_number_unsigned

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

## Example

??? example

    The following code exemplifies `is_number_unsigned()` for all JSON types.
    
    ```cpp
    --8<-- "examples/is_number_unsigned.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/is_number_unsigned.output"
    ```

## Version history

- Added in version 2.0.0.
