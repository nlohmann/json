# nlohmann::basic_json::type

```
constexpr value_t type() const noexcept;
```

Return the type of the JSON value as a value from the [`value_t`](https://json.nlohmann.me/api/basic_json/value_t/index.md) enumeration.

## Return value

the type of the JSON value

| Value type                | return value               |
| ------------------------- | -------------------------- |
| `null`                    | `value_t::null`            |
| boolean                   | `value_t::boolean`         |
| string                    | `value_t::string`          |
| number (integer)          | `value_t::number_integer`  |
| number (unsigned integer) | `value_t::number_unsigned` |
| number (floating-point)   | `value_t::number_float`    |
| object                    | `value_t::object`          |
| array                     | `value_t::array`           |
| binary                    | `value_t::binary`          |
| discarded                 | `value_t::discarded`       |

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Examples

Example

The following code exemplifies `type()` for all JSON types.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON values
    json j_null;
    json j_boolean = true;
    json j_number_integer = -17;
    json j_number_unsigned = 42u;
    json j_number_float = 23.42;
    json j_object = {{"one", 1}, {"two", 2}};
    json j_array = {1, 2, 4, 8, 16};
    json j_string = "Hello, world";

    // call type()
    std::cout << std::boolalpha;
    std::cout << (j_null.type() == json::value_t::null) << '\n';
    std::cout << (j_boolean.type() == json::value_t::boolean) << '\n';
    std::cout << (j_number_integer.type() == json::value_t::number_integer) << '\n';
    std::cout << (j_number_unsigned.type() == json::value_t::number_unsigned) << '\n';
    std::cout << (j_number_float.type() == json::value_t::number_float) << '\n';
    std::cout << (j_object.type() == json::value_t::object) << '\n';
    std::cout << (j_array.type() == json::value_t::array) << '\n';
    std::cout << (j_string.type() == json::value_t::string) << '\n';
}
```

Output:

```
true
true
true
true
true
true
true
true
```

## Version history

- Added in version 1.0.0.
- Added unsigned integer type in version 2.0.0.
- Added binary type in version 3.8.0.
