# Access with default value: value

## Overview

In many situations, such as configuration files, missing values are not exceptional, but may be treated as if a default value was present. For this case, use [`value(key, default_value)`](https://json.nlohmann.me/api/basic_json/value/index.md) which takes the key you want to access and a default value in case there is no value stored with that key. This is equivalent to Python's `dict.get(key, default)`.

## Example

Example

Consider the following JSON value:

```
{
    "logOutput": "result.log",
    "append": true
}
```

Assume the value is parsed to a `json` variable `j`.

| expression                            | value                                         |
| ------------------------------------- | --------------------------------------------- |
| `j`                                   | `{"logOutput": "result.log", "append": true}` |
| `j.value("logOutput", "logfile.log")` | `"result.log"`                                |
| `j.value("append", true)`             | `true`                                        |
| `j.value("append", false)`            | `true`                                        |
| `j.value("logLevel", "verbose")`      | `"verbose"`                                   |

## Notes

Exceptions

- With string keys, `value` can only be used with objects. For other types, a [`basic_json::type_error`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error306) is thrown.
- With JSON Pointers, `value` can be used with both objects and arrays. For other types (null, boolean, number, string), a [`basic_json::type_error`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error306) is thrown.

Return type

The value function is a template, and the return type of the function is determined by the type of the provided default value unless otherwise specified. This can have unexpected effects. In the example below, we store a 64-bit unsigned integer. We get exactly that value when using [`operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md). However, when we call `value` and provide `0` as default value, then `-1` is returned. This occurs, because `0` has type `int` which overflows when handling the value `18446744073709551615`.

To address this issue, either provide a correctly typed default value or use the template parameter to specify the desired return type. Note that this issue occurs even when a value is stored at the provided key, and the default value is not used as the return value.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    json j = json::parse(R"({"uint64": 18446744073709551615})");

    std::cout << "operator[]:                " << j["uint64"] << '\n'
              << "default value (int):       " << j.value("uint64", 0) << '\n'
              << "default value (uint64_t):  " << j.value("uint64", std::uint64_t(0)) << '\n'
              << "explicit return value type: " << j.value<std::uint64_t>("uint64", 0) << '\n';
}
```

Output:

```
operator[]:                18446744073709551615
default value (int):       -1
default value (uint64_t):  18446744073709551615
explicit return value type: 18446744073709551615
```

## See also

- [`value`](https://json.nlohmann.me/api/basic_json/value/index.md) for access with default value
- documentation on [checked access](https://json.nlohmann.me/features/element_access/checked_access/index.md)
