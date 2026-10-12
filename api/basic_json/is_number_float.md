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
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using json = nlohmann::json;
    
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
    
        // call is_number_float()
        std::cout << std::boolalpha;
        std::cout << j_null.is_number_float() << '\n';
        std::cout << j_boolean.is_number_float() << '\n';
        std::cout << j_number_integer.is_number_float() << '\n';
        std::cout << j_number_unsigned_integer.is_number_float() << '\n';
        std::cout << j_number_float.is_number_float() << '\n';
        std::cout << j_object.is_number_float() << '\n';
        std::cout << j_array.is_number_float() << '\n';
        std::cout << j_string.is_number_float() << '\n';
        std::cout << j_binary.is_number_float() << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    false
    false
    false
    false
    true
    false
    false
    false
    false
    
    ```

## See also

- [is_number()](is_number.md) check if the value is a number
- [is_number_integer()](is_number_integer.md) check if the value is an integer or unsigned integer number
- [is_number_unsigned()](is_number_unsigned.md) check if the value is an unsigned integer number

## Version history

- Added in version 1.0.0.
