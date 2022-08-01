# Checked access: at

## Overview

The [`at`](../../api/basic_json/at.md) member function performs checked access; that is, it returns a reference to the
desired value if it exists and throws a [`basic_json::out_of_range` exception](../../home/exceptions.md#out-of-range)
otherwise.

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

    | expression                    | value                                                                        |
    |-------------------------------|------------------------------------------------------------------------------|
    | `#!cpp j`                     | `#!json {"name": "Mary Smith", "age": 42, "hobbies": ["hiking", "reading"]}` |
    | `#!cpp j.at("name")`          | `#!json "Mary Smith"`                                                        |
    | `#!cpp j.at("age")`           | `#!json 42`                                                                  |
    | `#!cpp j.at("hobbies")`       | `#!json ["hiking", "reading"]`                                               |
    | `#!cpp j.at("hobbies").at(0)` | `#!json "hiking"`                                                            |
    | `#!cpp j.at("hobbies").at(1)` | `#!json "reading"`                                                           |

The return value is a reference, so it can be modified by the original value.

??? example "Write access"

    ```cpp
    j.at("name") = "John Smith";
    ```
    
    This code produces the following JSON value:
    
    ```json
    {
        "name": "John Smith",
        "age": 42,
        "hobbies": ["hiking", "reading"]
    }
    ```

When accessing an invalid index (i.e., an index greater than or equal to the array size) or the passed object key is
non-existing, an exception is thrown.

??? example "Accessing via invalid index or missing key"

    ```cpp
    j.at("hobbies").at(3) = "cooking";
    ```
    
    This code produces the following exception:
    
    ```
    [json.exception.out_of_range.401] array index 3 is out of range
    ```

    When you [extended diagnostic messages](../../home/exceptions.md#extended-diagnostic-messages) are enabled by
    defining [`JSON_DIAGNOSTICS`](../../api/macros/json_diagnostics.md), the exception further gives information where
    the key or index is missing or out of range.
    
    ```
    [json.exception.out_of_range.401] (/hobbies) array index 3 is out of range
    ```

## Notes


!!! failure "Exceptions"

    - [`at`](../../api/basic_json/at.md) can only be used with objects (with a string argument) or with arrays (with a
      numeric argument). For other types, a [`basic_json::type_error`](../../home/exceptions.md#jsonexceptiontype_error304)
      is thrown.
    - [`basic_json::out_of_range` exception](../../home/exceptions.md#out-of-range) exceptions are thrown if the
      provided key is not found in an object or the provided index is invalid.

## Summary

| scenario                          | non-const value                                | const value                                    |
|-----------------------------------|------------------------------------------------|------------------------------------------------|
| access to existing object key     | reference to existing value is returned        | const reference to existing value is returned  |
| access to valid array index       | reference to existing value is returned        | const reference to existing value is returned  |
| access to non-existing object key | `basic_json::out_of_range` exception is thrown | `basic_json::out_of_range` exception is thrown |
| access to invalid array index     | `basic_json::out_of_range` exception is thrown | `basic_json::out_of_range` exception is thrown |
