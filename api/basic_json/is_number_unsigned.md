# <small>nlohmann::basic_json::</small>is_number_unsigned

```cpp
constexpr bool is_number_unsigned() const noexcept;
```

This function returns `#!cpp true` if and only if the JSON value is an unsigned integer number. This excludes
floating-point and signed integer values.

If [`number_unsigned_t`](number_unsigned_t.md) is the same type as [`number_integer_t`](number_integer_t.md), every
integer is stored as `number_integer_t`, and this function always returns `#!cpp false`.
    
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
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
    int main()
    {
        // create JSON values
        json j_null;
        json j_boolean = true;
        json j_number_integer = 17;
        json j_number_unsigned_integer = 12345678987654321u;
        json j_number_float = 23.42;
        json j_object = {{"one", 1}, {"two", 2}};
        json j_array = {1, 2, 4, 8, 16};
        json j_string = "Hello, world";
        json j_binary = json::binary({1, 2, 3});
    
        // call is_number_unsigned()
        std::cout << std::boolalpha;
        std::cout << j_null.is_number_unsigned() << '\n';
        std::cout << j_boolean.is_number_unsigned() << '\n';
        std::cout << j_number_integer.is_number_unsigned() << '\n';
        std::cout << j_number_unsigned_integer.is_number_unsigned() << '\n';
        std::cout << j_number_float.is_number_unsigned() << '\n';
        std::cout << j_object.is_number_unsigned() << '\n';
        std::cout << j_array.is_number_unsigned() << '\n';
        std::cout << j_string.is_number_unsigned() << '\n';
        std::cout << j_binary.is_number_unsigned() << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    false
    false
    false
    true
    false
    false
    false
    false
    false
    
    ```

## See also

- [is_number()](is_number.md) check if the value is a number
- [is_number_integer()](is_number_integer.md) check if the value is an integer or unsigned integer number
- [is_number_float()](is_number_float.md) check if the value is a floating-point number
- [basic_json_view::is_number_unsigned](../basic_json_view/is_number_unsigned.md) - the same check on a zero-copy view

## Version history

- Added in version 2.0.0.
