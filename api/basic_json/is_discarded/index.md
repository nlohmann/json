# nlohmann::basic_json::is_discarded

```
constexpr bool is_discarded() const noexcept;
```

This function returns `true` for a JSON value if either:

- the value was discarded during parsing with a callback function (see [`parser_callback_t`](https://json.nlohmann.me/api/basic_json/parser_callback_t/index.md)), or
- the value is the result of parsing invalid JSON with parameter `allow_exceptions` set to `false`; see [`parse`](https://json.nlohmann.me/api/basic_json/parse/index.md) for more information.

## Return value

`true` if type is discarded, `false` otherwise.

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Notes

Comparisons

Discarded values are never compared equal with [`operator==`](https://json.nlohmann.me/api/basic_json/operator_eq/index.md). That is, checking whether a JSON value `j` is discarded will only work via:

```
j.is_discarded()
```

because

```
j == json::value_t::discarded
```

will always be `false`.

Removal during parsing with callback functions

When a value is discarded by a callback function (see [`parser_callback_t`](https://json.nlohmann.me/api/basic_json/parser_callback_t/index.md)) during parsing, then it is removed when it is part of a structured value. For instance, if the second value of an array is discarded, instead of `[null, discarded, false]`, the array `[null, false]` is returned. If the top-level value itself is discarded by the callback, the `parse` call returns a `null` value.

After a successful parse, this function always returns `false`: discarded values can only occur during parsing and are either removed when inside a structured value or replaced by `null` at the top level. The exception is parsing with `allow_exceptions` set to `false`: a parse error then yields a discarded value for which this function returns `true` (see [`parse`](https://json.nlohmann.me/api/basic_json/parse/index.md)).

## Examples

Example

The following code exemplifies `is_discarded()` for all JSON types.

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

    // call is_discarded()
    std::cout << std::boolalpha;
    std::cout << j_null.is_discarded() << '\n';
    std::cout << j_boolean.is_discarded() << '\n';
    std::cout << j_number_integer.is_discarded() << '\n';
    std::cout << j_number_unsigned_integer.is_discarded() << '\n';
    std::cout << j_number_float.is_discarded() << '\n';
    std::cout << j_object.is_discarded() << '\n';
    std::cout << j_array.is_discarded() << '\n';
    std::cout << j_string.is_discarded() << '\n';
    std::cout << j_binary.is_discarded() << '\n';
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
false
```

## Version history

- Added in version 1.0.0.
