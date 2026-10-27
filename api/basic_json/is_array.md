# <small>nlohmann::basic_json::</small>is_array

```cpp
constexpr bool is_array() const noexcept;
```

This function returns `#!cpp true` if and only if the JSON value is an array.
    
## Return value

`#!cpp true` if type is an array, `#!cpp false` otherwise.

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Examples

??? example

    The following code exemplifies `is_array()` for all JSON types.
    
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
    
        // call is_array()
        std::cout << std::boolalpha;
        std::cout << j_null.is_array() << '\n';
        std::cout << j_boolean.is_array() << '\n';
        std::cout << j_number_integer.is_array() << '\n';
        std::cout << j_number_unsigned_integer.is_array() << '\n';
        std::cout << j_number_float.is_array() << '\n';
        std::cout << j_object.is_array() << '\n';
        std::cout << j_array.is_array() << '\n';
        std::cout << j_string.is_array() << '\n';
        std::cout << j_binary.is_array() << '\n';
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
    true
    false
    false
    
    ```

## See also

- [`is_object`](is_object.md) - checks whether the JSON value is an object
- [`is_structured`](is_structured.md) - checks whether the JSON value is structured (array or object)
- [`type`](type.md) - returns the type of the JSON value
- [`array_t`](array_t.md) - the type used to store JSON arrays
- [`basic_json_view::is_array`](../basic_json_view/is_array.md) - the same check on a zero-copy view
- [Types](../../features/types/index.md) - the JSON value types and how they are stored

## Version history

- Added in version 1.0.0.
