# nlohmann::basic_json::is_number_integer

```
constexpr bool is_number_integer() const noexcept;
```

This function returns `true` if and only if the JSON value is a signed or unsigned integer number. This excludes floating-point values.

## Return value

`true` if type is an integer or unsigned integer number, `false` otherwise.

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Examples

Example

The following code exemplifies `is_number_integer()` for all JSON types.

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
    json j_number_unsigned_integer = 12345678987654321u;
    json j_number_float = 23.42;
    json j_object = {{"one", 1}, {"two", 2}};
    json j_array = {1, 2, 4, 8, 16};
    json j_string = "Hello, world";
    json j_binary = json::binary({1, 2, 3});

    // call is_number_integer()
    std::cout << std::boolalpha;
    std::cout << j_null.is_number_integer() << '\n';
    std::cout << j_boolean.is_number_integer() << '\n';
    std::cout << j_number_integer.is_number_integer() << '\n';
    std::cout << j_number_unsigned_integer.is_number_integer() << '\n';
    std::cout << j_number_float.is_number_integer() << '\n';
    std::cout << j_object.is_number_integer() << '\n';
    std::cout << j_array.is_number_integer() << '\n';
    std::cout << j_string.is_number_integer() << '\n';
    std::cout << j_binary.is_number_integer() << '\n';
}
```

Output:

```
false
false
true
true
false
false
false
false
false
```

## See also

- [is_number()](https://json.nlohmann.me/api/basic_json/is_number/index.md) check if the value is a number
- [is_number_unsigned()](https://json.nlohmann.me/api/basic_json/is_number_unsigned/index.md) check if the value is an unsigned integer number
- [is_number_float()](https://json.nlohmann.me/api/basic_json/is_number_float/index.md) check if the value is a floating-point number

## Version history

- Added in version 1.0.0.
- Extended to also return `true` for unsigned integers in 2.0.0.
