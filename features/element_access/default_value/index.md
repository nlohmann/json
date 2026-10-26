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

## Nested values

To read a value deep inside a document, pass a [JSON Pointer](https://json.nlohmann.me/features/json_pointer/index.md) instead of a key. The default value is returned if the value at the pointer does not exist, including the case that an intermediate key is missing. There is no need to check each level with [`contains`](https://json.nlohmann.me/api/basic_json/contains/index.md) first.

```
json j = {{"server", {{"port", 8080}}}, {"list", {10, 20}}};

int port = j.value("/server/port"_json_pointer, 80);        // 8080
int timeout = j.value("/server/limits/timeout"_json_pointer, 30); // 30 (missing intermediate key)
int second = j.value("/list/1"_json_pointer, 0);            // 20 (numeric tokens index arrays)
int third = j.value("/list/5"_json_pointer, 0);             // 0 (index out of range)

bool has_port = j.contains("/server/port"_json_pointer);    // true
bool has_host = j.contains("/server/host/name"_json_pointer); // false
```

If the path is only available as a dotted string such as `"server.port"`, do not build the pointer by concatenating `"/"` and the parts: keys containing `/` or `~` would be misinterpreted. Append each part as a reference token with [`operator/=`](https://json.nlohmann.me/api/json_pointer/operator_slasheq/index.md) instead. It escapes the token for you.

```
json::json_pointer to_pointer(const std::string& dotted)
{
    json::json_pointer ptr;
    std::istringstream in(dotted);
    for (std::string token; std::getline(in, token, '.');)
    {
        ptr /= token;
    }
    return ptr;
}

int port = j.value(to_pointer("server.port"), 80);          // 8080
int first = j.value(to_pointer("list.0"), 0);               // 10
```

The key `"a/b"` yields the pointer `"/a~1b"`; the dot-splitting itself is up to the caller, so keys containing `.` need a different separator.

## Notes

Exceptions

- With string keys, `value` can only be used with objects. For other types, a [`basic_json::type_error`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error306) is thrown.
- With JSON Pointers, `value` can be used with both objects and arrays. For other types (null, boolean, number, string), a [`basic_json::type_error`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error306) is thrown.

`null` and mistyped members are not missing

`value` returns the default value only if the key is **absent**. If the member exists, it is converted to the type of the default value, even if it is `null`. For `{"k": null}`, the call `j.value("k", 0)` throws a [`basic_json::type_error`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error302), and so does a member of another type such as a string where a number is expected. The same holds for JSON Pointers.

To treat `null` like a missing value, check for it explicitly:

```
int n = (j.contains("k") && !j["k"].is_null()) ? j["k"].get<int>() : 0;
```

With C++17, [`get<std::optional<T>>()`](https://json.nlohmann.me/api/basic_json/get/index.md) maps `null` to an empty optional. As [`at`](https://json.nlohmann.me/api/basic_json/at/index.md) throws [`out_of_range`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range403) for an absent key, use [`find`](https://json.nlohmann.me/api/basic_json/find/index.md) to cover both cases:

```
std::optional<int> n;                        // empty if "k" is absent or null
if (const auto it = j.find("k"); it != j.end())
{
    n = it->get<std::optional<int>>();       // still throws for a non-number such as "text"
}
```

Return type

The value function is a template, and the return type of the function is determined by the type of the provided default value unless otherwise specified. This can have unexpected effects. In the example below, we store a 64-bit unsigned integer. We get exactly that value when using [`operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md). However, when we call `value` and provide `0` as default value, then `-1` is returned. This occurs, because `0` has type `int` which overflows when handling the value `18446744073709551615`.

To address this issue, either provide a correctly typed default value or use the template parameter to specify the desired return type. Note that this issue occurs even when a value is stored at the provided key, and the default value is not used as the return value.

```
#include <iostream>
#include <nlohmann/json.hpp>

using nlohmann::json;

int main()
{
    json j = json::parse(R"({"uint64": 18446744073709551615})");

    std::cout << "operator[]:                " << j["uint64"] << '\n'
              << "default value (int):       " << j.value("uint64", 0) << '\n'
              << "default value (uint64_t):  " << j.value("uint64", static_cast<std::uint64_t>(0)) << '\n'
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
- documentation on [JSON Pointer](https://json.nlohmann.me/features/json_pointer/index.md)
- [`contains`](https://json.nlohmann.me/api/basic_json/contains/index.md) to check whether a key or JSON Pointer exists
- [`json_pointer::operator/=`](https://json.nlohmann.me/api/json_pointer/operator_slasheq/index.md) to build a pointer token by token
