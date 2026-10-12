# <small>nlohmann::json_pointer::</small>empty

```cpp
bool empty() const noexcept;
```

Return whether the pointer points to the root document.

## Return value

`#!cpp true` iff the JSON pointer points to the root document.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Examples

??? example

    The example shows the result of `empty` for different JSON Pointers.
     
    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using json = nlohmann::json;
    
    int main()
    {
        // different JSON Pointers
        json::json_pointer ptr0;
        json::json_pointer ptr1("");
        json::json_pointer ptr2("/foo");
        json::json_pointer ptr3("/foo/0");
    
        // call empty()
        std::cout << std::boolalpha
                  << "\"" << ptr0 << "\": " << ptr0.empty() << '\n'
                  << "\"" << ptr1 << "\": " << ptr1.empty() << '\n'
                  << "\"" << ptr2 << "\": " << ptr2.empty() << '\n'
                  << "\"" << ptr3 << "\": " << ptr3.empty() << std::endl;
    }
    
    ```
    
    Output:
    
    ```json
    "": true
    "": true
    "/foo": false
    "/foo/0": false
    
    ```

## See also

- [front](front.md) return first reference token
- [back](back.md) return last reference token
- [to_string](to_string.md) return a string representation of the JSON pointer

## Version history

Added in version 3.6.0.
