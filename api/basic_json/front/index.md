# nlohmann::basic_json::front

```
reference front();
const_reference front() const;
```

Returns a reference to the first element in the container. For a JSON container `c`, the expression `c.front()` is equivalent to `*c.begin()`.

## Return value

In the case of a structured type (array or object), a reference to the first element is returned. In the case of number, string, boolean, or binary values, a reference to the value is returned.

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

If the JSON value is `null`, exception [`invalid_iterator.214`](https://json.nlohmann.me/home/exceptions/#jsonexceptioninvalid_iterator214) is thrown.

## Complexity

Constant.

## Notes

Precondition

The array or object must not be empty. Calling `front` on an empty array or object yields undefined behavior.

## Examples

Example

The following code shows an example for `front()`.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

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

```
true
17
23.42
1
1
"Hello, world"
```

## See also

- [back](https://json.nlohmann.me/api/basic_json/back/index.md) to access the last element

## Version history

- Added in version 1.0.0.
- Adjusted code to return reference to binary values in version 3.8.0.
