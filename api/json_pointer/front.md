# <small>nlohmann::json_pointer::</small>front

```cpp
const string_t& front() const;
```

Return the first reference token.

## Return value

First reference token.

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Exceptions

Throws [out_of_range.405](../../home/exceptions.md#jsonexceptionout_of_range405) if the JSON pointer has no parent.

## Complexity

Constant.

## Examples

??? example

    The example shows the usage of `front`.
     
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
        std::cout << "first reference token of \"" << ptr1 << "\" is \"" << ptr1.front() << "\"\n"
                  << "first reference token of \"" << ptr2 << "\" is \"" << ptr2.front() << "\"" << std::endl;
    }
    
    ```
    
    Output:
    
    ```json
    first reference token of "/foo" is "foo"
    first reference token of "/foo/0" is "foo"
    
    ```

## See also

- [back](back.md) return last reference token
- [pop_front](pop_front.md) remove the first reference token
- [push_front](push_front.md) append an unescaped token at the start of the pointer

## Version history

- Added in version 3.13.0.
