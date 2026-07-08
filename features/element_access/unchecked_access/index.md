# Unchecked access: operator[]

## Overview

Elements in a JSON object and a JSON array can be accessed via [`operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md) similar to a `std::map` and a `std::vector`, respectively.

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

| expression        | value                                                                 |
| ----------------- | --------------------------------------------------------------------- |
| `j`               | `{"name": "Mary Smith", "age": 42, "hobbies": ["hiking", "reading"]}` |
| `j["name"]`       | `"Mary Smith"`                                                        |
| `j["age"]`        | `42`                                                                  |
| `j["hobbies"]`    | `["hiking", "reading"]`                                               |
| `j["hobbies"][0]` | `"hiking"`                                                            |
| `j["hobbies"][1]` | `"reading"`                                                           |

The return value is a reference, so it can modify the original value. In case the passed object key is non-existing, a `null` value is inserted which can immediately be overwritten.

Write access

```
j["name"] = "John Smith";
j["maidenName"] = "Jones";
```

This code produces the following JSON value:

```
{
    "name": "John Smith",
    "maidenName": "Jones",
    "age": 42,
    "hobbies": ["hiking", "reading"]
}
```

When accessing an invalid index (i.e., an index greater than or equal to the array size), the JSON array is resized such that the passed index is the new maximal index. Intermediate values are filled with `null`.

Filling up arrays with `null` values

```
j["hobbies"][0] = "running";
j["hobbies"][3] = "cooking";
```

This code produces the following JSON value:

```
{
    "name": "John Smith",
    "maidenName": "Jones",
    "age": 42,
    "hobbies": ["running", "reading", null, "cooking"]
}
```

## Notes

Design rationale

The library behaves differently to `std::vector` and `std::map`:

- `std::vector::operator[]` never inserts a new element.
- `std::map::operator[]` is not available for const values.

The type `json` wraps all JSON value types. It would be impossible to remove [`operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md) for const objects. At the same time, inserting elements for non-const objects is really convenient as it avoids awkward `insert` calls. To this end, we decided to have an inserting non-const behavior for both arrays and objects.

Info

The access is unchecked. In case the passed object key does not exist or the passed array index is invalid, no exception is thrown.

Danger

- It is **undefined behavior** to access a const object with a non-existing key.
- It is **undefined behavior** to access a const array with an invalid index.
- In debug mode, an **assertion** will fire in both cases. You can disable assertions by defining the preprocessor symbol `NDEBUG` or redefine the macro [`JSON_ASSERT(x)`](https://json.nlohmann.me/features/macros/#json_assertx). See the documentation on [runtime assertions](https://json.nlohmann.me/features/assertions/index.md) for more information.

Exceptions

`operator[]` can only be used with objects (with a string argument) or with arrays (with a numeric argument). For other types, a [`basic_json::type_error`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error305) is thrown.

## Summary

| scenario                          | non-const value                                                                                                                        | const value                                                                                                      |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| access to existing object key     | reference to existing value is returned                                                                                                | const reference to existing value is returned                                                                    |
| access to valid array index       | reference to existing value is returned                                                                                                | const reference to existing value is returned                                                                    |
| access to non-existing object key | reference to newly inserted `null` value is returned                                                                                   | **undefined behavior**; [runtime assertion](https://json.nlohmann.me/features/assertions/index.md) in debug mode |
| access to invalid array index     | reference to newly inserted `null` value is returned; any index between previous maximal index and passed index are filled with `null` | **undefined behavior**; [runtime assertion](https://json.nlohmann.me/features/assertions/index.md) in debug mode |
