# Checked access: at

## Overview

The [`at`](https://json.nlohmann.me/api/basic_json/at/index.md) member function performs checked access; that is, it returns a reference to the desired value if it exists and throws a [`basic_json::out_of_range` exception](https://json.nlohmann.me/home/exceptions/#out-of-range) otherwise.

Read access

Consider the following JSON value:

```
{
    "name": "Mary Smith",
    "age": 42,
    "hobbies": ["hiking", "reading"]
}
```

Assume the value is parsed to a `json` variable `j`.

| expression              | value                                                                 |
| ----------------------- | --------------------------------------------------------------------- |
| `j`                     | `{"name": "Mary Smith", "age": 42, "hobbies": ["hiking", "reading"]}` |
| `j.at("name")`          | `"Mary Smith"`                                                        |
| `j.at("age")`           | `42`                                                                  |
| `j.at("hobbies")`       | `["hiking", "reading"]`                                               |
| `j.at("hobbies").at(0)` | `"hiking"`                                                            |
| `j.at("hobbies").at(1)` | `"reading"`                                                           |

The return value is a reference, so it can be used to modify the original value.

Write access

```
j.at("name") = "John Smith";
```

This code produces the following JSON value:

```
{
    "name": "John Smith",
    "age": 42,
    "hobbies": ["hiking", "reading"]
}
```

When accessing an invalid index (i.e., an index greater than or equal to the array size) or the passed object key is non-existing, an exception is thrown.

Accessing via invalid index or missing key

```
j.at("hobbies").at(3) = "cooking";
```

This code produces the following exception:

```
[json.exception.out_of_range.401] array index 3 is out of range
```

When [extended diagnostic messages](https://json.nlohmann.me/home/exceptions/#extended-diagnostic-messages) are enabled by defining [`JSON_DIAGNOSTICS`](https://json.nlohmann.me/api/macros/json_diagnostics/index.md), the exception further gives information where the key or index is missing or out of range.

```
[json.exception.out_of_range.401] (/hobbies) array index 3 is out of range
```

## Notes

Exceptions

- [`at`](https://json.nlohmann.me/api/basic_json/at/index.md) can only be used with objects (with a string argument) or with arrays (with a numeric argument). For other types, a [`basic_json::type_error`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error304) is thrown.
- [`basic_json::out_of_range` exception](https://json.nlohmann.me/home/exceptions/#out-of-range) exceptions are thrown if the provided key is not found in an object or the provided index is invalid.

## Summary

| scenario                          | non-const value                                | const value                                    |
| --------------------------------- | ---------------------------------------------- | ---------------------------------------------- |
| access to existing object key     | reference to existing value is returned        | const reference to existing value is returned  |
| access to valid array index       | reference to existing value is returned        | const reference to existing value is returned  |
| access to non-existing object key | `basic_json::out_of_range` exception is thrown | `basic_json::out_of_range` exception is thrown |
| access to invalid array index     | `basic_json::out_of_range` exception is thrown | `basic_json::out_of_range` exception is thrown |
