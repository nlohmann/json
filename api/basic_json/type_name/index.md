# nlohmann::basic_json::type_name

```
const char* type_name() const noexcept;
```

Returns the type name as string to be used in error messages -- usually to indicate that a function was called on a wrong JSON type.

## Return value

a string representation of the type ([`value_t`](https://json.nlohmann.me/api/basic_json/value_t/index.md)):

| Value type                                         | return value  |
| -------------------------------------------------- | ------------- |
| `null`                                             | `"null"`      |
| boolean                                            | `"boolean"`   |
| string                                             | `"string"`    |
| number (integer, unsigned integer, floating-point) | `"number"`    |
| object                                             | `"object"`    |
| array                                              | `"array"`     |
| binary                                             | `"binary"`    |
| discarded                                          | `"discarded"` |
| invalid (corrupted value)                          | `"invalid"`   |

The "invalid" type

The `"invalid"` return value indicates a corrupted JSON value — this can occur if an enum value falls outside the range of valid `value_t` values. This is useful for diagnosing data corruption or internal errors.

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Examples

Example

The following code exemplifies `type_name()` for all JSON types.

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

    // call type_name()
    std::cout << j_null << " is a " << j_null.type_name() << '\n';
    std::cout << j_boolean << " is a " << j_boolean.type_name() << '\n';
    std::cout << j_number_integer << " is a " << j_number_integer.type_name() << '\n';
    std::cout << j_number_unsigned << " is a " << j_number_unsigned.type_name() << '\n';
    std::cout << j_number_float << " is a " << j_number_float.type_name() << '\n';
    std::cout << j_object << " is an " << j_object.type_name() << '\n';
    std::cout << j_array << " is an " << j_array.type_name() << '\n';
    std::cout << j_string << " is a " << j_string.type_name() << '\n';
}
```

Output:

```
null is a null
true is a boolean
-17 is a number
42 is a number
23.42 is a number
{"one":1,"two":2} is an object
[1,2,4,8,16] is an array
"Hello, world" is a string
```

## Version history

- Added in version 1.0.0.
- Part of the public API version since 2.1.0.
- Changed return value to `const char*` and added `noexcept` in version 3.0.0.
- Added support for binary type in version 3.8.0.
- Added `"invalid"` return value for corrupted JSON values in version 3.13.0.
