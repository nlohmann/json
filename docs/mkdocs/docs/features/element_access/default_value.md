# Access with default value: value

## Overview

In many situations such as configuration files, missing values are not exceptional, but may be treated as if a default value was present.

??? example

    Consider the following JSON value:
    
    ```json
    {
        "logOutput": "result.log",
        "append": true
    }
    ```
    
    Assume the value is parsed to a `json` variable `j`.

    | expression | value |
    | ---------- | ----- |
    | `#!cpp j`  | `#!json {"logOutput": "result.log", "append": true}` |
    | `#!cpp j.value("logOutput", "logfile.log")`  | `#!json "result.log"` |
    | `#!cpp j.value("append", true)`  | `#!json true` |
    | `#!cpp j.value("append", false)`  | `#!json true` |
    | `#!cpp j.value("logLevel", "verbose")`  | `#!json "verbose"` |

## Note

!!! failure "Exceptions"

    - `value` can only be used with objects. For other types, a [`basic_json::type_error`](../../home/exceptions.md#jsonexceptiontype_error306) is thrown.
