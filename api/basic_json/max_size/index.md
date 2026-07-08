# nlohmann::basic_json::max_size

```
size_type max_size() const noexcept;
```

Returns the maximum number of elements a JSON value is able to hold due to system or library implementation limitations, i.e. `std::distance(begin(), end())` for the JSON value.

## Return value

The return value depends on the different types and is defined as follows:

| Value type | return value                                                                    |
| ---------- | ------------------------------------------------------------------------------- |
| null       | `0` (same as [`size()`](https://json.nlohmann.me/api/basic_json/size/index.md)) |
| boolean    | `1` (same as [`size()`](https://json.nlohmann.me/api/basic_json/size/index.md)) |
| string     | `1` (same as [`size()`](https://json.nlohmann.me/api/basic_json/size/index.md)) |
| number     | `1` (same as [`size()`](https://json.nlohmann.me/api/basic_json/size/index.md)) |
| binary     | `1` (same as [`size()`](https://json.nlohmann.me/api/basic_json/size/index.md)) |
| object     | result of function `object_t::max_size()`                                       |
| array      | result of function `array_t::max_size()`                                        |

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant, as long as [`array_t`](https://json.nlohmann.me/api/basic_json/array_t/index.md) and [`object_t`](https://json.nlohmann.me/api/basic_json/object_t/index.md) satisfy the [Container](https://en.cppreference.com/w/cpp/named_req/Container) concept; that is, their `max_size()` functions have constant complexity.

## Notes

This function does not return the maximal length of a string stored as JSON value -- it returns the maximal number of string elements the JSON value can store which is `1`.

## Examples

Example

The following code calls `max_size()` on the different value types.

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
    json j_array = {1, 2, 4, 8, 16};
    json j_string = "Hello, world";

    // call max_size()
    std::cout << j_null.max_size() << '\n';
    std::cout << j_boolean.max_size() << '\n';
    std::cout << j_number_integer.max_size() << '\n';
    std::cout << j_number_float.max_size() << '\n';
    std::cout << j_object.max_size() << '\n';
    std::cout << j_array.max_size() << '\n';
    std::cout << j_string.max_size() << '\n';
}
```

Output:

```
0
1
1
1
115292150460684697
576460752303423487
1
```

Note the output is platform-dependent.

## Version history

- Added in version 1.0.0.
- Extended to return `1` for binary types in version 3.8.0.
