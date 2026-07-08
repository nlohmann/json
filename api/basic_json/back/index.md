# nlohmann::basic_json::back

```
reference back();

const_reference back() const;
```

Returns a reference to the last element in the container. For a JSON container `c`, the expression `c.back()` is equivalent to

```
auto tmp = c.end();
--tmp;
return *tmp;
```

## Return value

In the case of a structured type (array or object), a reference to the last element is returned. In the case of number, string, boolean, or binary values, a reference to the value is returned.

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

If the JSON value is `null`, exception [`invalid_iterator.214`](https://json.nlohmann.me/home/exceptions/#jsonexceptioninvalid_iterator214) is thrown.

## Complexity

Constant.

## Notes

Precondition

The array or object must not be empty. Calling `back` on an empty array or object yields undefined behavior.

## Examples

Example

The following code shows an example for `back()`.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON values
    json j_boolean = true;
    json j_number_integer = 17;
    json j_number_float = 23.42;
    json j_object = {{"one", 1}, {"two", 2}};
    json j_object_empty(json::value_t::object);
    json j_array = {1, 2, 4, 8, 16};
    json j_array_empty(json::value_t::array);
    json j_string = "Hello, world";

    // call back()
    std::cout << j_boolean.back() << '\n';
    std::cout << j_number_integer.back() << '\n';
    std::cout << j_number_float.back() << '\n';
    std::cout << j_object.back() << '\n';
    //std::cout << j_object_empty.back() << '\n';  // undefined behavior
    std::cout << j_array.back() << '\n';
    //std::cout << j_array_empty.back() << '\n';   // undefined behavior
    std::cout << j_string.back() << '\n';

    // back() called on a null value
    try
    {
        json j_null;
        j_null.back();
    }
    catch (const json::invalid_iterator& e)
    {
        std::cout << e.what() << '\n';
    }
}
```

Output:

```
true
17
23.42
2
16
"Hello, world"
[json.exception.invalid_iterator.214] cannot get value
```

## See also

- [front](https://json.nlohmann.me/api/basic_json/front/index.md) to access the first element

## Version history

- Added in version 1.0.0.
- Adjusted code to return reference to binary values in version 3.8.0.
