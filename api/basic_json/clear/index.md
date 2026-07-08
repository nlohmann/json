# nlohmann::basic_json::clear

```
void clear() noexcept;
```

Clears the content of a JSON value and resets it to the default value as if [`basic_json(value_t)`](https://json.nlohmann.me/api/basic_json/basic_json/index.md) would have been called with the current value type from [`type()`](https://json.nlohmann.me/api/basic_json/type/index.md):

| Value type | initial value        |
| ---------- | -------------------- |
| null       | `null`               |
| boolean    | `false`              |
| string     | `""`                 |
| number     | `0`                  |
| binary     | An empty byte vector |
| object     | `{}`                 |
| array      | `[]`                 |

Has the same effect as calling

```
*this = basic_json(type());
```

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Linear in the size of the JSON value.

## Notes

All iterators, pointers, and references related to this container are invalidated.

## Examples

Example

The example below shows the effect of `clear()` to different JSON types.

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

    // call clear()
    j_null.clear();
    j_boolean.clear();
    j_number_integer.clear();
    j_number_float.clear();
    j_object.clear();
    j_array.clear();
    j_string.clear();

    // serialize the cleared values()
    std::cout << j_null << '\n';
    std::cout << j_boolean << '\n';
    std::cout << j_number_integer << '\n';
    std::cout << j_number_float << '\n';
    std::cout << j_object << '\n';
    std::cout << j_array << '\n';
    std::cout << j_string << '\n';
}
```

Output:

```
null
false
0
0.0
{}
[]
""
```

## Version history

- Added in version 1.0.0.
- Added support for binary types in version 3.8.0.
