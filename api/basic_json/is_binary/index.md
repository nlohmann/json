# nlohmann::basic_json::is_binary

```
constexpr bool is_binary() const noexcept;
```

This function returns `true` if and only if the JSON value is a binary array.

## Return value

`true` if type is binary, `false` otherwise.

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Examples

Example

The following code exemplifies `is_binary()` for all JSON types.

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

    // call is_binary()
    std::cout << std::boolalpha;
    std::cout << j_null.is_binary() << '\n';
    std::cout << j_boolean.is_binary() << '\n';
    std::cout << j_number_integer.is_binary() << '\n';
    std::cout << j_number_unsigned_integer.is_binary() << '\n';
    std::cout << j_number_float.is_binary() << '\n';
    std::cout << j_object.is_binary() << '\n';
    std::cout << j_array.is_binary() << '\n';
    std::cout << j_string.is_binary() << '\n';
    std::cout << j_binary.is_binary() << '\n';
}
```

Output:

```
false
false
false
false
false
false
false
false
true
```

## See also

- [is_primitive](https://json.nlohmann.me/api/basic_json/is_primitive/index.md) checks whether the JSON value is primitive
- [binary_t](https://json.nlohmann.me/api/basic_json/binary_t/index.md) the type used to store binary values
- [get_binary](https://json.nlohmann.me/api/basic_json/get_binary/index.md) returns a reference to the stored binary value

## Version history

- Added in version 3.8.0.
