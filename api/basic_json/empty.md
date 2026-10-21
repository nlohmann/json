# <small>nlohmann::basic_json::</small>empty

```cpp
bool empty() const noexcept;
```

Checks if a JSON value has no elements (i.e., whether its [`size()`](size.md) is `0`).
    
## Return value

The return value depends on the different types and is defined as follows:

| Value type | return value                           |
|------------|----------------------------------------|
| null       | `#!cpp true`                           |
| boolean    | `#!cpp false`                          |
| string     | `#!cpp false`                          |
| number     | `#!cpp false`                          |
| binary     | `#!cpp false`                          |
| object     | result of function `object_t::empty()` |
| array      | result of function `array_t::empty()`  |

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant, as long as [`array_t`](array_t.md) and [`object_t`](object_t.md) satisfy the
[Container](https://en.cppreference.com/w/cpp/named_req/Container) concept; that is, their `empty()` functions have
constant complexity.

## Possible implementation

```cpp
bool empty() const noexcept
{
    return size() == 0;
}
```

## Notes

This function does not return whether a string stored as JSON value is empty -- it returns whether the JSON container
itself is empty which is `#!cpp false` in the case of a string.

## Examples

??? example

    The following code uses `empty()` to check if a JSON object contains any elements.
    
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
        json j_object = {{"one", 1}, {"two", 2}};
        json j_object_empty(json::value_t::object);
        json j_array = {1, 2, 4, 8, 16};
        json j_array_empty(json::value_t::array);
        json j_string = "Hello, world";
    
        // call empty()
        std::cout << std::boolalpha;
        std::cout << j_null.empty() << '\n';
        std::cout << j_boolean.empty() << '\n';
        std::cout << j_number_integer.empty() << '\n';
        std::cout << j_number_float.empty() << '\n';
        std::cout << j_object.empty() << '\n';
        std::cout << j_object_empty.empty() << '\n';
        std::cout << j_array.empty() << '\n';
        std::cout << j_array_empty.empty() << '\n';
        std::cout << j_string.empty() << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    true
    false
    false
    false
    false
    true
    false
    true
    false
    
    ```

## See also

- [size](size.md) returns the number of elements
- [clear](clear.md) clears the content and resets the value to the default value
- [basic_json_view::empty](../basic_json_view/empty.md) - the same check on a zero-copy view

## Version history

- Added in version 1.0.0.
- Extended to return `#!cpp false` for binary types in version 3.8.0.
