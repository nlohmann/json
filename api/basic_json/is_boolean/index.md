# nlohmann::basic_json::is_boolean

```
constexpr bool is_boolean() const noexcept;
```

This function returns `true` if and only if the JSON value is `true` or `false`.

## Return value

`true` if type is boolean, `false` otherwise.

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Examples

Example

The following code exemplifies `is_boolean()` for all JSON types.

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

    // call is_boolean()
    std::cout << std::boolalpha;
    std::cout << j_null.is_boolean() << '\n';
    std::cout << j_boolean.is_boolean() << '\n';
    std::cout << j_number_integer.is_boolean() << '\n';
    std::cout << j_number_unsigned_integer.is_boolean() << '\n';
    std::cout << j_number_float.is_boolean() << '\n';
    std::cout << j_object.is_boolean() << '\n';
    std::cout << j_array.is_boolean() << '\n';
    std::cout << j_string.is_boolean() << '\n';
    std::cout << j_binary.is_boolean() << '\n';
}
```

Output:

```
false
true
false
false
false
false
false
false
false
```

## Version history

- Added in version 1.0.0.
