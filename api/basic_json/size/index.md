# nlohmann::basic_json::size

```
size_type size() const noexcept;
```

Returns the number of elements in a JSON value.

## Return value

The return value depends on the different types and is defined as follows:

| Value type | return value                        |
| ---------- | ----------------------------------- |
| null       | `0`                                 |
| boolean    | `1`                                 |
| string     | `1`                                 |
| number     | `1`                                 |
| binary     | `1`                                 |
| object     | result of function object_t::size() |
| array      | result of function array_t::size()  |

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant, as long as [`array_t`](https://json.nlohmann.me/api/basic_json/array_t/index.md) and [`object_t`](https://json.nlohmann.me/api/basic_json/object_t/index.md) satisfy the [Container](https://en.cppreference.com/w/cpp/named_req/Container) concept; that is, their `size()` functions have constant complexity.

## Notes

This function does not return the length of a string stored as JSON value -- it returns the number of elements in the JSON value which is `1` in the case of a string.

## Examples

Example

The following code calls `size()` on the different value types.

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

    // call size()
    std::cout << j_null.size() << '\n';
    std::cout << j_boolean.size() << '\n';
    std::cout << j_number_integer.size() << '\n';
    std::cout << j_number_float.size() << '\n';
    std::cout << j_object.size() << '\n';
    std::cout << j_object_empty.size() << '\n';
    std::cout << j_array.size() << '\n';
    std::cout << j_array_empty.size() << '\n';
    std::cout << j_string.size() << '\n';
}
```

Output:

```
0
1
1
1
2
0
5
0
1
```

## Version history

- Added in version 1.0.0.
- Extended to return `1` for binary types in version 3.8.0.
