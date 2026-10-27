# <small>nlohmann::basic_json::</small>is_string

```cpp
constexpr bool is_string() const noexcept;
```

This function returns `#!cpp true` if and only if the JSON value is a string.
    
## Return value

`#!cpp true` if type is a string, `#!cpp false` otherwise.

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Examples

??? example

    The following code exemplifies `is_string()` for all JSON types.
    
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
        json j_number_float = 23.42;
        json j_number_unsigned_integer = 12345678987654321u;
        json j_object = {{"one", 1}, {"two", 2}};
        json j_array = {1, 2, 4, 8, 16};
        json j_string = "Hello, world";
        json j_binary = json::binary({1, 2, 3});
    
        // call is_string()
        std::cout << std::boolalpha;
        std::cout << j_null.is_string() << '\n';
        std::cout << j_boolean.is_string() << '\n';
        std::cout << j_number_integer.is_string() << '\n';
        std::cout << j_number_unsigned_integer.is_string() << '\n';
        std::cout << j_number_float.is_string() << '\n';
        std::cout << j_object.is_string() << '\n';
        std::cout << j_array.is_string() << '\n';
        std::cout << j_string.is_string() << '\n';
        std::cout << j_binary.is_string() << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    false
    false
    false
    false
    false
    false
    false
    true
    false
    
    ```

## See also

- [`is_primitive`](is_primitive.md) - checks whether the JSON value is primitive
- [`type`](type.md) - returns the type of the JSON value
- [`string_t`](string_t.md) - the type used to store JSON strings
- [`basic_json_view::is_string`](../basic_json_view/is_string.md) - the same check on a zero-copy view
- [Types](../../features/types/index.md) - the JSON value types and how they are stored

## Version history

- Added in version 1.0.0.
