# <small>nlohmann::basic_json::</small>is_primitive

```cpp
constexpr bool is_primitive() const noexcept;
```

This function returns `#!cpp true` if and only if the JSON type is primitive (string, number, boolean, `#!json null`,
binary).
    
## Return value

`#!cpp true` if type is primitive (string, number, boolean, `#!json null`, or binary), `#!cpp false` otherwise.

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Possible implementation

```cpp
constexpr bool is_primitive() const noexcept
{
    return is_null() || is_string() || is_boolean() || is_number() || is_binary();
}
```

## Notes

The term *primitive* stems from [RFC 8259](https://tools.ietf.org/html/rfc8259):

> JSON can represent four primitive types (strings, numbers, booleans, and null) and two structured types (objects and
> arrays).

This library extends primitive types to binary types, because binary types are roughly comparable to strings. Hence,
`is_primitive()` returns `#!cpp true` for binary values.

## Examples

??? example

    The following code exemplifies `is_primitive()` for all JSON types.
    
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
        json j_number_float = 23.42;
        json j_number_unsigned_integer = 12345678987654321u;
        json j_object = {{"one", 1}, {"two", 2}};
        json j_array = {1, 2, 4, 8, 16};
        json j_string = "Hello, world";
        json j_binary = json::binary({1, 2, 3});
    
        // call is_primitive()
        std::cout << std::boolalpha;
        std::cout << j_null.is_primitive() << '\n';
        std::cout << j_boolean.is_primitive() << '\n';
        std::cout << j_number_integer.is_primitive() << '\n';
        std::cout << j_number_unsigned_integer.is_primitive() << '\n';
        std::cout << j_number_float.is_primitive() << '\n';
        std::cout << j_object.is_primitive() << '\n';
        std::cout << j_array.is_primitive() << '\n';
        std::cout << j_string.is_primitive() << '\n';
        std::cout << j_binary.is_primitive() << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    true
    true
    true
    true
    true
    false
    false
    true
    true
    
    ```

## See also

- [is_structured()](is_structured.md) returns whether the JSON value is structured
- [is_null()](is_null.md) returns whether the JSON value is `null`
- [is_string()](is_string.md) returns whether the JSON value is a string
- [is_boolean()](is_boolean.md) returns whether the JSON value is a boolean
- [is_number()](is_number.md) returns whether the JSON value is a number
- [is_binary()](is_binary.md) returns whether the JSON value is a binary array

## Version history

- Added in version 1.0.0.
- Extended to return `#!cpp true` for binary types in version 3.8.0.
