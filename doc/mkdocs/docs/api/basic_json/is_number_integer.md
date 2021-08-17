# basic_json::is_number_integer

```cpp
constexpr bool is_number_integer() const noexcept;
```

This function returns `#!cpp true` if and only if the JSON value is a signed or unsigned integer number. This excludes
floating-point values.
    
## Return value

`#!cpp true` if type is an integer or unsigned integer number, `#!cpp false` otherwise.

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Example

??? example

    The following code exemplifies `is_number_integer()` for all JSON types.
    
    ```cpp
    --8<-- "examples/is_number_integer.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/is_number_integer.output"
    ```

## Version history

- Added in version 1.0.0.
- Extended to also return `#!cpp true` for unsigned integers in 2.0.0.
