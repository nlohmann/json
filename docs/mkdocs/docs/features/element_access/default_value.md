# Access with default value: value

## Overview

In many situations, such as configuration files, missing values are not exceptional, but may be treated as if a default
value was present. For this case, use [`value(key, default_value)`](../../api/basic_json/value.md) which takes the key
you want to access and a default value in case there is no value stored with that key. This is equivalent to Python's
`dict.get(key, default)`.

## Example

??? example

    Consider the following JSON value:
    
    ```json
    {
        "logOutput": "result.log",
        "append": true
    }
    ```
    
    Assume the value is parsed to a `json` variable `j`.

    | expression                                  | value                                                |
    |---------------------------------------------|------------------------------------------------------|
    | `#!cpp j`                                   | `#!json {"logOutput": "result.log", "append": true}` |
    | `#!cpp j.value("logOutput", "logfile.log")` | `#!json "result.log"`                                |
    | `#!cpp j.value("append", true)`             | `#!json true`                                        |
    | `#!cpp j.value("append", false)`            | `#!json true`                                        |
    | `#!cpp j.value("logLevel", "verbose")`      | `#!json "verbose"`                                   |

## Nested values

To read a value deep inside a document, pass a [JSON Pointer](../json_pointer.md) instead of a key. The default value is
returned if the value at the pointer does not exist, including the case that an intermediate key is missing. There is
no need to check each level with [`contains`](../../api/basic_json/contains.md) first.

```cpp
json j = {{"server", {{"port", 8080}}}, {"list", {10, 20}}};

int port = j.value("/server/port"_json_pointer, 80);        // 8080
int timeout = j.value("/server/limits/timeout"_json_pointer, 30); // 30 (missing intermediate key)
int second = j.value("/list/1"_json_pointer, 0);            // 20 (numeric tokens index arrays)
int third = j.value("/list/5"_json_pointer, 0);             // 0 (index out of range)

bool has_port = j.contains("/server/port"_json_pointer);    // true
bool has_host = j.contains("/server/host/name"_json_pointer); // false
```

If the path is only available as a dotted string such as `#!cpp "server.port"`, do not build the pointer by
concatenating `#!cpp "/"` and the parts: keys containing `/` or `~` would be misinterpreted. Append each part as a
reference token with [`operator/=`](../../api/json_pointer/operator_slasheq.md) instead. It escapes the token for you.

```cpp
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

The key `#!cpp "a/b"` yields the pointer `#!cpp "/a~1b"`; the dot-splitting itself is up to the caller, so keys
containing `.` need a different separator.

## Notes

!!! failure "Exceptions"

    - With string keys, `value` can only be used with objects. For other types, a [`basic_json::type_error`](../../home/exceptions.md#jsonexceptiontype_error306) is thrown.
    - With JSON Pointers, `value` can be used with both objects and arrays. For other types (null, boolean, number, string), a [`basic_json::type_error`](../../home/exceptions.md#jsonexceptiontype_error306) is thrown.

!!! warning "`null` and mistyped members are not missing"

    `value` returns the default value only if the key is **absent**. If the member exists, it is converted to the type
    of the default value, even if it is `#!json null`. For `#!json {"k": null}`, the call `#!cpp j.value("k", 0)` throws
    a [`basic_json::type_error`](../../home/exceptions.md#jsonexceptiontype_error302), and so does a member of another
    type such as a string where a number is expected. The same holds for JSON Pointers.

    To treat `#!json null` like a missing value, check for it explicitly:

    ```cpp
    int n = (j.contains("k") && !j["k"].is_null()) ? j["k"].get<int>() : 0;
    ```

    With C++17, [`get<std::optional<T>>()`](../../api/basic_json/get.md) maps `#!json null` to an empty optional. As
    [`at`](../../api/basic_json/at.md) throws [`out_of_range`](../../home/exceptions.md#jsonexceptionout_of_range403)
    for an absent key, use [`find`](../../api/basic_json/find.md) to cover both cases:

    ```cpp
    std::optional<int> n;                        // empty if "k" is absent or null
    if (const auto it = j.find("k"); it != j.end())
    {
        n = it->get<std::optional<int>>();       // still throws for a non-number such as "text"
    }
    ```

!!! warning "Return type"

    The value function is a template, and the return type of the function is determined by the type of the provided
    default value unless otherwise specified. This can have unexpected effects. In the example below, we store a 64-bit
    unsigned integer. We get exactly that value when using [`operator[]`](../../api/basic_json/operator%5B%5D.md).
    However, when we call `value` and provide `#!c 0` as default value, then `#!c -1` is returned. This occurs,
    because `#!c 0` has type `#!c int` which overflows when handling the value `#!c 18446744073709551615`.

    To address this issue, either provide a correctly typed default value or use the template parameter to specify the
    desired return type. Note that this issue occurs even when a value is stored at the provided key, and the default
    value is not used as the return value.

    ```cpp
    --8<-- "examples/value__return_type.cpp"
    ```

    Output:
    
    ```json
    --8<-- "examples/value__return_type.output"
    ```

## See also

- [`value`](../../api/basic_json/value.md) for access with default value
- documentation on [checked access](checked_access.md)
- documentation on [JSON Pointer](../json_pointer.md)
- [`contains`](../../api/basic_json/contains.md) to check whether a key or JSON Pointer exists
- [`json_pointer::operator/=`](../../api/json_pointer/operator_slasheq.md) to build a pointer token by token
