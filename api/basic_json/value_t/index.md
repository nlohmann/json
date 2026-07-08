# nlohmann::basic_json::value_t

```
enum class value_t : std::uint8_t {
    null,
    object,
    array,
    string,
    boolean,
    number_integer,
    number_unsigned,
    number_float,
    binary,
    discarded
};
```

This enumeration collects the different JSON types. It is internally used to distinguish the stored values, and the functions [`is_null`](https://json.nlohmann.me/api/basic_json/is_null/index.md), [`is_object`](https://json.nlohmann.me/api/basic_json/is_object/index.md), [`is_array`](https://json.nlohmann.me/api/basic_json/is_array/index.md), [`is_string`](https://json.nlohmann.me/api/basic_json/is_string/index.md), [`is_boolean`](https://json.nlohmann.me/api/basic_json/is_boolean/index.md), [`is_number`](https://json.nlohmann.me/api/basic_json/is_number/index.md) (with [`is_number_integer`](https://json.nlohmann.me/api/basic_json/is_number_integer/index.md), [`is_number_unsigned`](https://json.nlohmann.me/api/basic_json/is_number_unsigned/index.md), and [`is_number_float`](https://json.nlohmann.me/api/basic_json/is_number_float/index.md)), [`is_discarded`](https://json.nlohmann.me/api/basic_json/is_discarded/index.md), [`is_binary`](https://json.nlohmann.me/api/basic_json/is_binary/index.md), [`is_primitive`](https://json.nlohmann.me/api/basic_json/is_primitive/index.md), and [`is_structured`](https://json.nlohmann.me/api/basic_json/is_structured/index.md) rely on it.

## Notes

Ordering

The order of types is as follows:

1. `null`
1. `boolean`
1. `number_integer`, `number_unsigned`, `number_float`
1. `object`
1. `array`
1. `string`
1. `binary`

`discarded` is unordered.

Types of numbers

There are three enumerators for numbers (`number_integer`, `number_unsigned`, and `number_float`) to distinguish between different types of numbers:

- [`number_unsigned_t`](https://json.nlohmann.me/api/basic_json/number_unsigned_t/index.md) for unsigned integers
- [`number_integer_t`](https://json.nlohmann.me/api/basic_json/number_integer_t/index.md) for signed integers
- [`number_float_t`](https://json.nlohmann.me/api/basic_json/number_float_t/index.md) for floating-point numbers or to approximate integers which do not fit into the limits of their respective type

Comparison operators

`operator<` and `operator<=>` (since C++20) are overloaded and compare according to the ordering described above. Until C++20 all other relational and equality operators yield results according to the integer value of each enumerator. Since C++20 some compilers consider the *rewritten candidates* generated from `operator<=>` during overload resolution, while others do not. For predictable and portable behavior use:

- `operator<` or `operator<=>` when wanting to compare according to the order described above
- `operator==` or `operator!=` when wanting to compare according to each enumerators integer value

## Examples

Example

The following code how `type()` queries the `value_t` for all JSON types.

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
