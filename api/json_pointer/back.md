# <small>nlohmann::json_pointer::</small>back

```cpp
const string_t& back() const;
```

Return the last reference token.

## Return value

Last reference token.

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Exceptions

Throws [out_of_range.405](../../home/exceptions.md#jsonexceptionout_of_range405) if the JSON pointer has no parent.

## Complexity

Constant.

## Examples

??? example

    The example shows the usage of `back`.
     
    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using json = nlohmann::json;
    
    int main()
    {
        // different JSON Pointers
        json::json_pointer ptr1("/foo");
        json::json_pointer ptr2("/foo/0");
    
        // call empty()
        std::cout << "last reference token of \"" << ptr1 << "\" is \"" << ptr1.back() << "\"\n"
                  << "last reference token of \"" << ptr2 << "\" is \"" << ptr2.back() << "\"" << std::endl;
    }
    
    ```
    
    Output:
    
    ```json
    last reference token of "/foo" is "foo"
    last reference token of "/foo/0" is "0"
    
    ```

## See also

- [front](front.md) return first reference token
- [pop_back](pop_back.md) remove the last reference token
- [push_back](push_back.md) append an unescaped token at the end of the pointer
- [parent_pointer](parent_pointer.md) returns the parent of this JSON pointer

## Version history

- Added in version 3.6.0.
- Changed return type to `string_t` in version 3.11.0.
