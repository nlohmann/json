# Access with default value: value

## Overview

In many situations, such as configuration files, missing values are not exceptional, but may be treated as if a default
value was present. For this case, use [`value(key, default_value)`](../../api/basic_json/value.md) which takes the key
you want to access and a default value in case there is no value stored with that key.

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

## Notes

!!! failure "Exceptions"

    - `value` can only be used with objects. For other types, a [`basic_json::type_error`](../../home/exceptions.md#jsonexceptiontype_error306) is thrown.

!!! warning "Return type"

    The value function is a template, and the return type of the function is determined by the type of the provided
    default value unless otherwise specified. This can have unexpected effects. In the example below, we store a 64-bit
    unsigned integer. We get exactly that value when using [`operator[]`](../../api/basic_json/operator[].md). However,
    when we call `value` and provide `#!c 0` as default value, then `#!c -1` is returned. The occurs, because `#!c 0`
    has type `#!c int` which overflows when handling the value `#!c 18446744073709551615`.

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
