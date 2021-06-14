# basic_json::is_number_float

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

## Example

??? example

    The following code exemplifies `is_number_float()` for all JSON types.
    
    ```cpp
    --8<-- "examples/is_number_float.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/is_number_float.output"
    ```

## Version history

- Added in version 1.0.0.
