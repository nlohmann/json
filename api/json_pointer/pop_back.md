# <small>nlohmann::json_pointer::</small>pop_back

```cpp
void pop_back();
```

Remove the last reference token.

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Exceptions

Throws [out_of_range.405](../../home/exceptions.md#jsonexceptionout_of_range405) if the JSON pointer has no parent.

## Complexity

Constant.

## Examples

??? example

    The example shows the usage of `pop_back`.
     
    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using json = nlohmann::json;
    
    int main()
    {
        // create empty JSON Pointer
        json::json_pointer ptr("/foo/bar/baz");
        std::cout << "\"" << ptr << "\"\n";
    
        // call pop_back()
        ptr.pop_back();
        std::cout << "\"" << ptr << "\"\n";
    
        ptr.pop_back();
        std::cout << "\"" << ptr << "\"\n";
    
        ptr.pop_back();
        std::cout << "\"" << ptr << "\"\n";
    }
    
    ```
    
    Output:
    
    ```json
    "/foo/bar/baz"
    "/foo/bar"
    "/foo"
    ""
    
    ```

## See also

- [back](back.md) return last reference token
- [push_back](push_back.md) append an unescaped token at the end of the pointer
- [parent_pointer](parent_pointer.md) returns the parent of this JSON pointer

## Version history

Added in version 3.6.0.
