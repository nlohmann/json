# <small>nlohmann::basic_json::</small>front

```cpp
reference front();
const_reference front() const;
```

Returns a reference to the first element in the container. For a JSON container `#!cpp c`, the expression
`#!cpp c.front()` is equivalent to `#!cpp *c.begin()`.
    
## Return value

In the case of a structured type (array or object), a reference to the first element is returned. In the case of number,
string, boolean, or binary values, a reference to the value is returned.

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

If the JSON value is `#!json null`, exception
[`invalid_iterator.214`](../../home/exceptions.md#jsonexceptioninvalid_iterator214) is thrown.

## Complexity

Constant.

## Notes

!!! info "Precondition"

    The array or object must not be empty. Calling `front` on an empty array or object yields undefined behavior.

## Examples

??? example

    The following code shows an example for `front()`.
     
    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
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
    
        // call front()
        //std::cout << j_null.front() << '\n';          // would throw
        std::cout << j_boolean.front() << '\n';
        std::cout << j_number_integer.front() << '\n';
        std::cout << j_number_float.front() << '\n';
        std::cout << j_object.front() << '\n';
        //std::cout << j_object_empty.front() << '\n';  // undefined behavior
        std::cout << j_array.front() << '\n';
        //std::cout << j_array_empty.front() << '\n';   // undefined behavior
        std::cout << j_string.front() << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    true
    17
    23.42
    1
    1
    "Hello, world"
    
    ```

## See also

- [back](back.md) to access the last element
- [basic_json_view::front](../basic_json_view/front.md) - the same access on a zero-copy view (document order, not
  sorted; duplicate keys are visited)

## Version history

- Added in version 1.0.0.
- Binary values are supported since version 3.8.0.
