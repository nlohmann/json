# <small>nlohmann::basic_json::</small>is_structured

```cpp
constexpr bool is_structured() const noexcept;
```

This function returns `#!cpp true` if and only if the JSON type is structured (array or object).
    
## Return value

`#!cpp true` if type is structured (array or object), `#!cpp false` otherwise.

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Possible implementation

```cpp
constexpr bool is_structured() const noexcept
{
    return is_array() || is_object();
}
```

## Notes

The term *structured* stems from [RFC 8259](https://tools.ietf.org/html/rfc8259):

> JSON can represent four primitive types (strings, numbers, booleans, and null) and two structured types (objects and
> arrays).

Note that though strings are containers in C++, they are treated as primitive values in JSON.

## Examples

??? example

    The following code exemplifies `is_structured()` for all JSON types.
    
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
    
        // call is_structured()
        std::cout << std::boolalpha;
        std::cout << j_null.is_structured() << '\n';
        std::cout << j_boolean.is_structured() << '\n';
        std::cout << j_number_integer.is_structured() << '\n';
        std::cout << j_number_unsigned_integer.is_structured() << '\n';
        std::cout << j_number_float.is_structured() << '\n';
        std::cout << j_object.is_structured() << '\n';
        std::cout << j_array.is_structured() << '\n';
        std::cout << j_string.is_structured() << '\n';
        std::cout << j_binary.is_structured() << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    false
    false
    false
    false
    false
    true
    true
    false
    false
    
    ```

## See also

- [`is_primitive()`](is_primitive.md) - returns whether JSON value is primitive
- [`is_array()`](is_array.md) - returns whether the value is an array
- [`is_object()`](is_object.md) - returns whether the value is an object
- [`basic_json_view::is_structured`](../basic_json_view/is_structured.md) - the same check on a zero-copy view
- [Types](../../features/types/index.md) - the JSON value types and how they are stored

## Version history

- Added in version 1.0.0.
