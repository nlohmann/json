# <small>nlohmann::json_pointer::</small>operator/=

```cpp
// (1)
json_pointer& operator/=(const json_pointer& ptr);

// (2)
json_pointer& operator/=(string_t token);

// (3)
json_pointer& operator/=(std::size_t array_idx)
```

1. append another JSON pointer at the end of this JSON pointer
2. append an unescaped reference token at the end of this JSON pointer
3. append an array index at the end of this JSON pointer

## Parameters

`ptr` (in)
:    JSON pointer to append

`token` (in)
:    reference token to append

`array_idx` (in)
:    array index to append

## Return value

1. JSON pointer with `ptr` appended
2. JSON pointer with `token` appended without escaping `token`
3. JSON pointer with `array_idx` appended

## Exception safety

1. Basic guarantee: if an exception is thrown (for instance, if copying a reference token fails), the JSON pointer is
   left in a valid state, but it may contain some of the reference tokens of `ptr`.
2. Strong guarantee: if an exception is thrown, there are no changes to the JSON pointer.
3. Strong guarantee: if an exception is thrown, there are no changes to the JSON pointer.

## Complexity

1. Linear in the length of `ptr`.
2. Amortized constant.
3. Amortized constant.

## Examples

??? example

    The example shows the usage of `operator/=`.
     
    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using json = nlohmann::json;
    
    int main()
    {
        // create a JSON pointer
        json::json_pointer ptr("/foo");
        std::cout << "\"" << ptr << "\"\n";
    
        // append a JSON Pointer
        ptr /= json::json_pointer("/bar/baz");
        std::cout << "\"" << ptr << "\"\n";
    
        // append a string
        ptr /= "fob";
        std::cout << "\"" << ptr << "\"\n";
    
        // append an array index
        ptr /= 42;
        std::cout << "\"" << ptr << "\"" << std::endl;
    }
    
    ```
    
    Output:
    
    ```json
    "/foo"
    "/foo/bar/baz"
    "/foo/bar/baz/fob"
    "/foo/bar/baz/fob/42"
    
    ```

## See also

- [operator/](operator_slash.md) create JSON Pointer by appending
- [push_back](push_back.md) append an unescaped token at the end of the pointer

## Version history

1. Added in version 3.6.0.
2. Added in version 3.6.0. Changed type of `token` to `string_t` in version 3.11.0.
3. Added in version 3.6.0.
