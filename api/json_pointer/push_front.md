# <small>nlohmann::json_pointer::</small>push_front

```cpp
void push_front(const string_t& token);

void push_front(string_t&& token);
```

Append an unescaped token at the start of the reference pointer.

## Parameters

`token` (in)
:   token to add

## Exception safety

Basic guarantee: if an exception is thrown (for instance, if copying the reference token fails), the JSON pointer is
left in a valid state, but its reference tokens may have changed.

## Complexity

Linear in the number of reference tokens in the `json_pointer`.

## Examples

??? example

    The example shows the result of `push_front` for different JSON Pointers.
     
    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
    int main()
    {
        // create empty JSON Pointer
        json::json_pointer ptr;
        std::cout << "\"" << ptr << "\"\n";
    
        // call push_front()
        ptr.push_front("foo");
        std::cout << "\"" << ptr << "\"\n";
    
        ptr.push_front("0");
        std::cout << "\"" << ptr << "\"\n";
    
        ptr.push_front("bar");
        std::cout << "\"" << ptr << "\"\n";
    }
    
    ```
    
    Output:
    
    ```json
    ""
    "/foo"
    "/0/foo"
    "/bar/0/foo"
    
    ```

## See also

- [`front`](front.md) - return first reference token
- [`pop_front`](pop_front.md) - remove the first reference token

## Version history

- Added in version 3.13.0.
