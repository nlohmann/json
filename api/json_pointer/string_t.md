# <small>nlohmann::json_pointer::</small>string_t
```cpp
using string_t = RefStringType;
```

The string type used for the reference tokens making up the JSON pointer.

See [`basic_json::string_t`](../basic_json/string_t.md) for more information.

## Examples

??? example

    The example shows the type `string_t` and its relation to `basic_json::string_t`.
     
    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
    int main()
    {
        json::json_pointer::string_t s = "This is a string.";
    
        std::cout << s << '\n';
    
        std::cout << std::boolalpha << std::is_same<json::json_pointer::string_t, json::string_t>::value << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    This is a string.
    true
    
    ```

## See also

- [`basic_json::string_t`](../basic_json/string_t.md) - type used to store JSON strings
- [`to_string`](to_string.md) - return a string representation of the JSON pointer

## Version history

- Added in version 3.11.0.
