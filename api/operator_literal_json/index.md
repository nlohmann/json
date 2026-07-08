# nlohmann::operator""\_json

```
json operator ""_json(const char* s, std::size_t n);
json operator ""_json(const char8_t* s, std::size_t n);  // since C++20
```

This operator implements a user-defined string literal for JSON objects. It can be used by adding `_json` to a string literal and returns a [`json`](https://json.nlohmann.me/api/json/index.md) object if no parse error occurred.

It is recommended to bring the operator into scope using any of the following lines:

```
using nlohmann::literals::operator ""_json;
using namespace nlohmann::literals;
using namespace nlohmann::json_literals;
using namespace nlohmann::literals::json_literals;
using namespace nlohmann;
```

This is suggested to ease migration to the next major version release of the library. See [`JSON_USE_GLOBAL_UDLS`](https://json.nlohmann.me/api/macros/json_use_global_udls/#notes) for details.

## Parameters

`s` (in) : a string representation of a JSON object

`n` (in) : length of string `s`

## Return value

[`json`](https://json.nlohmann.me/api/json/index.md) value parsed from `s`

## Exceptions

The function can throw anything that [`parse(s, s+n)`](https://json.nlohmann.me/api/basic_json/parse/index.md) would throw.

## Complexity

Linear.

## Examples

Example

The following code shows how to create JSON values from string literals.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace nlohmann::literals;

int main()
{
    json j = R"( {"hello": "world", "answer": 42} )"_json;

    std::cout << std::setw(2) << j << '\n';
}
```

Output:

```
{
  "answer": 42,
  "hello": "world"
}
```

## See also

- [Creating JSON values](https://json.nlohmann.me/features/creating_values/index.md) - the article on creating JSON values

## Version history

- Added in version 1.0.0.
- Moved to namespace `nlohmann::literals::json_literals` in 3.11.0.
- Added `char8_t*` overload in 3.12.x.
