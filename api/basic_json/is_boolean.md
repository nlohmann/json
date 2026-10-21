# <small>nlohmann::basic_json::</small>is_boolean

```cpp
constexpr bool is_boolean() const noexcept;
```

This function returns `#!cpp true` if and only if the JSON value is `#!json true` or `#!json false`.
    
## Return value

`#!cpp true` if type is boolean, `#!cpp false` otherwise.

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Examples

??? example

    The following code exemplifies `is_boolean()` for all JSON types.
    
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
    
        // call is_boolean()
        std::cout << std::boolalpha;
        std::cout << j_null.is_boolean() << '\n';
        std::cout << j_boolean.is_boolean() << '\n';
        std::cout << j_number_integer.is_boolean() << '\n';
        std::cout << j_number_unsigned_integer.is_boolean() << '\n';
        std::cout << j_number_float.is_boolean() << '\n';
        std::cout << j_object.is_boolean() << '\n';
        std::cout << j_array.is_boolean() << '\n';
        std::cout << j_string.is_boolean() << '\n';
        std::cout << j_binary.is_boolean() << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    false
    true
    false
    false
    false
    false
    false
    false
    false
    
    ```

## See also

- [boolean_t](boolean_t.md) the type used to store JSON booleans
- [is_primitive](is_primitive.md) checks whether the JSON value is primitive
- [basic_json_view::is_boolean](../basic_json_view/is_boolean.md) - the same check on a zero-copy view

## Version history

- Added in version 1.0.0.
