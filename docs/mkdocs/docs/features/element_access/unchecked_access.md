# Unchecked access: operator[]

## Overview

Elements in a JSON object and a JSON array can be accessed via [`operator[]`](../../api/basic_json/operator%5B%5D.md)
similar to a `#!cpp std::map` and a `#!cpp std::vector`, respectively.

??? example "Read access"

    Consider the following JSON value:
    
    ```json
    {
        "name": "Mary Smith",
        "age": 42,
        "hobbies": ["hiking", "reading"]
    }
    ```
    
    Assume the value is parsed to a `json` variable `j`.

    | expression              | value                                                                        |
    |-------------------------|------------------------------------------------------------------------------|
    | `#!cpp j`               | `#!json {"name": "Mary Smith", "age": 42, "hobbies": ["hiking", "reading"]}` |
    | `#!cpp j["name"]`       | `#!json "Mary Smith"`                                                        |
    | `#!cpp j["age"]`        | `#!json 42`                                                                  |
    | `#!cpp j["hobbies"]`    | `#!json ["hiking", "reading"]`                                               |
    | `#!cpp j["hobbies"][0]` | `#!json "hiking"`                                                            |
    | `#!cpp j["hobbies"][1]` | `#!json "reading"`                                                           |

The return value is a reference, so it can modify the original value. In case the passed object key is non-existing, a
`#!json null` value is inserted which can be immediately be overwritten.

??? example "Write access"

    ```cpp
    j["name"] = "John Smith";
    j["maidenName"] = "Jones";
    ```
    
    This code produces the following JSON value:
    
    ```json
    {
        "name": "John Smith",
        "maidenName": "Jones",
        "age": 42,
        "hobbies": ["hiking", "reading"]
    }
    ```

When accessing an invalid index (i.e., an index greater than or equal to the array size), the JSON array is resized such
that the passed index is the new maximal index. Intermediate values are filled with `#!json null`.

??? example "Filling up arrays with `#!json null` values"

    ```cpp
    j["hobbies"][0] = "running";
    j["hobbies"][3] = "cooking";
    ```
    
    This code produces the following JSON value:
    
    ```json
    {
        "name": "John Smith",
        "maidenName": "Jones",
        "age": 42,
        "hobbies": ["running", "reading", null, "cooking"]
    }
    ```

## Notes

!!! info "Design rationale"

    The library behaves differently to `#!cpp std::vector` and `#!cpp std::map`:
    
    - `#!cpp std::vector::operator[]` never inserts a new element.
    - `#!cpp std::map::operator[]` is not available for const values.
    
    The type `#!cpp json` wraps all JSON value types. It would be impossible to remove
    [`operator[]`](../../api/basic_json/operator%5B%5D.md) for const objects. At the same time, inserting elements for
    non-const objects is really convenient as it avoids awkward `insert` calls. To this end, we decided to have an
    inserting non-const behavior for both arrays and objects.

!!! info

    The access is unchecked. In case the passed object key does not exist or the passed array index is invalid, no
    exception is thrown.

!!! danger

    - It is **undefined behavior** to access a const object with a non-existing key.
    - It is **undefined behavior** to access a const array with an invalid index.
    - In debug mode, an **assertion** will fire in both cases. You can disable assertions by defining the preprocessor
      symbol `#!cpp NDEBUG` or redefine the macro [`JSON_ASSERT(x)`](../macros.md#json_assertx). See the documentation
      on [runtime assertions](../assertions.md) for more information.

!!! failure "Exceptions"

    `operator[]` can only be used with objects (with a string argument) or with arrays (with a numeric argument). For other types, a [`basic_json::type_error`](../../home/exceptions.md#jsonexceptiontype_error305) is thrown.

## Summary

| scenario                          | non-const value                                                                                                                                      | const value                                                                 |
|-----------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------|
| access to existing object key     | reference to existing value is returned                                                                                                              | const reference to existing value is returned                               |
| access to valid array index       | reference to existing value is returned                                                                                                              | const reference to existing value is returned                               |
| access to non-existing object key | reference to newly inserted `#!json null` value is returned                                                                                          | **undefined behavior**; [runtime assertion](../assertions.md) in debug mode |
| access to invalid array index     | reference to newly inserted `#!json null` value is returned; any index between previous maximal index and passed index are filled with `#!json null` | **undefined behavior**; [runtime assertion](../assertions.md) in debug mode |
