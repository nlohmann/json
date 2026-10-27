# <small>nlohmann::json_pointer::</small>pop_front

```cpp
void pop_front();
```

Remove the first reference token.

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Exceptions

Throws [out_of_range.405](../../home/exceptions.md#jsonexceptionout_of_range405) if the JSON pointer has no parent.

## Complexity

Linear in the number of reference tokens in the `json_pointer`.

## Examples

??? example

    The example shows the usage of `pop_front`.
     
    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
    int main()
    {
        // create empty JSON Pointer
        json::json_pointer ptr("/foo/bar/baz");
        std::cout << "\"" << ptr << "\"\n";
    
        // call pop_front()
        ptr.pop_front();
        std::cout << "\"" << ptr << "\"\n";
    
        ptr.pop_front();
        std::cout << "\"" << ptr << "\"\n";
    
        ptr.pop_front();
        std::cout << "\"" << ptr << "\"\n";
    }
    
    ```
    
    Output:
    
    ```json
    "/foo/bar/baz"
    "/bar/baz"
    "/baz"
    ""
    
    ```

## See also

- [`front`](front.md) - return first reference token
- [`push_front`](push_front.md) - append an unescaped token at the start of the pointer

## Version history

- Added in version 3.13.0.
