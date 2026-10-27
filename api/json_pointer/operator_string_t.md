# <small>nlohmann::json_pointer::</small>operator string_t

```cpp
operator string_t() const
```

Return a string representation of the JSON pointer.

## Return value

A string representation of the JSON pointer

## Possible implementation

```cpp
operator string_t() const
{
    return to_string();
}
```

## Notes

!!! warning "Deprecation"

    This function is deprecated in favor of [`to_string`](to_string.md) and will be removed in a future major version
    release.

    See the [migration guide](../../integration/migration_guide.md#json-pointers) for how to update existing code.

## Examples

??? example

    The example shows how JSON Pointers can be implicitly converted to strings.
     
    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
    int main()
    {
        // different JSON Pointers
        json::json_pointer ptr1("/foo/0");
        json::json_pointer ptr2("/a~1b");
    
        // implicit conversion to string
        std::string s;
        s += ptr1;
        s += "\n";
        s += ptr2;
    
        std::cout << s << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    /foo/0
    /a~1b
    
    ```

## See also

- [`to_string`](to_string.md) - return a string representation of the JSON pointer
- [`string_t`](../basic_json/string_t.md) - type for strings

## Version history

- Added in version 2.0.0.
- Changed type to `string_t` and deprecated in version 3.11.0.
