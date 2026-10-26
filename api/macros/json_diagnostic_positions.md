# JSON_DIAGNOSTIC_POSITIONS

```cpp
#define JSON_DIAGNOSTIC_POSITIONS /* value */
```

This macro enables position diagnostics for generated JSON objects.

When enabled, two new member functions [`start_pos()`](../basic_json/start_pos.md) and
[`end_pos()`](../basic_json/end_pos.md) are added to [`basic_json`](../basic_json/index.md) values. If the value was
created by calling the[`parse`](../basic_json/parse.md) function, then these functions allow querying the byte positions
of the value in the input it was parsed from. In case the value was constructed by other means, `std::string::npos` is
returned.

[`start_pos()`](../basic_json/start_pos.md) returns the position of the first character of a given value in the original
JSON string, while [`end_pos()`](../basic_json/end_pos.md) returns the position of the character _following_ the last
character. For objects and arrays, the first and last characters correspond to the opening or closing braces/brackets,
respectively. For primitive values, the first and last character represents the opening and closing quotes (strings) or
the first and last character of the field's numerical or predefined value (`true`, `false`, `null`), respectively.

| JSON type | return value [`start_pos()`](../basic_json/start_pos.md) | return value [`end_pos()`](../basic_json/end_pos.md) |
|-----------|----------------------------------------------------------|------------------------------------------------------|
| object    | position of the opening `{`                              | position after the closing `}`                       |
| array     | position of the opening `[`                              | position after the closing `]`                       |
| string    | position of the opening `"`                              | position after the closing `"`                       |
| number    | position of the first character                          | position after the last character                    |
| boolean   | position of `t` for `true` and `f` for `false`           | position after `e`                                   |
| null      | position of `n`                                          | position after `l`                                   |

Given the above, [`end_pos()`](../basic_json/end_pos.md)` - `[`start_pos()`](../basic_json/start_pos.md) for a JSON
value provides the length of the parsed JSON string for that value, including the opening or closing braces, brackets,
or quotes.

Note that enabling this macro increases the size of every JSON value by two `std::size_t` fields and adds slight runtime
overhead to parsing, copying JSON value objects, and the generation of error messages for exceptions. It also causes
these values to be reported in those error messages.

## Default definition

The default value is `0` (position diagnostics are switched off).

```cpp
#define JSON_DIAGNOSTIC_POSITIONS 0
```

When the macro is not defined, the library will define it to its default value.

## Notes

!!! note "CMake option"

    Diagnostic positions can also be controlled with the CMake option
    [`JSON_Diagnostic_Positions`](../../integration/cmake.md#json_diagnostic_positions) (`OFF` by default)
    which defines `JSON_DIAGNOSTIC_POSITIONS` accordingly.

!!! note "Availability"

    Diagnostic positions are only available if the value was created by the [`parse`](../basic_json/parse.md) function.
    The [`sax_parse`](../basic_json/sax_parse.md) function or all other means to create a JSON value **do not** set the
    diagnostic positions and [`start_pos()`](../basic_json/start_pos.md) and [`end_pos()`](../basic_json/end_pos.md)
    will only return `std::string::npos` for these values.

!!! warning "Invalidation"

    The returned positions are only valid as long as the JSON value is not changed. The positions are *not* updated
    when the JSON value is changed.

## Examples

??? example "Example: retrieving positions"

    ```cpp
    #include <iostream>
    
    #define JSON_DIAGNOSTIC_POSITIONS 1
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
    int main()
    {
        std::string json_string = R"(
        {
            "address": {
                "street": "Fake Street",
                "housenumber": 1
            }
        }
        )";
        json j = json::parse(json_string);
    
        std::cout << "Root diagnostic positions: \n";
        std::cout << "\tstart_pos: " << j.start_pos() << '\n';
        std::cout << "\tend_pos:" << j.end_pos() << "\n";
        std::cout << "Original string: \n";
        std::cout << "{\n        \"address\": {\n            \"street\": \"Fake Street\",\n            \"housenumber\": 1\n        }\n    }" << "\n";
        std::cout << "Parsed string: \n";
        std::cout << json_string.substr(j.start_pos(), j.end_pos() - j.start_pos()) << "\n\n";
    
        std::cout << "address diagnostic positions: \n";
        std::cout << "\tstart_pos:" << j["address"].start_pos() << '\n';
        std::cout << "\tend_pos:" << j["address"].end_pos() << "\n\n";
        std::cout << "Original string: \n";
        std::cout << "{            \"street\": \"Fake Street\",\n            \"housenumber\": 1\n        }" << "\n";
        std::cout << "Parsed string: \n";
        std::cout << json_string.substr(j["address"].start_pos(), j["address"].end_pos() - j["address"].start_pos()) << "\n\n";
    
        std::cout << "street diagnostic positions: \n";
        std::cout << "\tstart_pos:" << j["address"]["street"].start_pos() << '\n';
        std::cout << "\tend_pos:" << j["address"]["street"].end_pos() << "\n\n";
        std::cout << "Original string: \n";
        std::cout << "\"Fake Street\"" << "\n";
        std::cout << "Parsed string: \n";
        std::cout << json_string.substr(j["address"]["street"].start_pos(), j["address"]["street"].end_pos() - j["address"]["street"].start_pos()) << "\n\n";
    
        std::cout << "housenumber diagnostic positions: \n";
        std::cout << "\tstart_pos:" << j["address"]["housenumber"].start_pos() << '\n';
        std::cout << "\tend_pos:" << j["address"]["housenumber"].end_pos() << "\n\n";
        std::cout << "Original string: \n";
        std::cout << "1" << "\n";
        std::cout << "Parsed string: \n";
        std::cout << json_string.substr(j["address"]["housenumber"].start_pos(), j["address"]["housenumber"].end_pos() - j["address"]["housenumber"].start_pos()) << "\n\n";
    }
    
    ```
    
    Output:

    ```
    Root diagnostic positions: 
    	start_pos: 5
    	end_pos:109
    Original string: 
    {
            "address": {
                "street": "Fake Street",
                "housenumber": 1
            }
        }
    Parsed string: 
    {
            "address": {
                "street": "Fake Street",
                "housenumber": 1
            }
        }
    
    address diagnostic positions: 
    	start_pos:26
    	end_pos:103
    
    Original string: 
    {            "street": "Fake Street",
                "housenumber": 1
            }
    Parsed string: 
    {
                "street": "Fake Street",
                "housenumber": 1
            }
    
    street diagnostic positions: 
    	start_pos:50
    	end_pos:63
    
    Original string: 
    "Fake Street"
    Parsed string: 
    "Fake Street"
    
    housenumber diagnostic positions: 
    	start_pos:92
    	end_pos:93
    
    Original string: 
    1
    Parsed string: 
    1
    
    
    ```

    The output shows the start/end positions of all the objects and fields in the JSON string.

??? example "Example: using only diagnostic positions in exceptions"

    ```cpp
    #include <iostream>
    
    #define JSON_DIAGNOSTIC_POSITIONS 1
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
    /* Demonstration of type error exception with diagnostic positions support enabled */
    int main()
    {
        //Invalid json string - housenumber type must be int instead of string
        const std::string json_invalid_string = R"(
        {
            "address": {
                "street": "Fake Street",
                "housenumber": "1"
            }
        }
        )";
        json j = json::parse(json_invalid_string);
        try
        {
            int housenumber = j["address"]["housenumber"];
            std::cout << housenumber;
        }
        catch (const json::exception& e)
        {
            std::cout << e.what() << '\n';
        }
    }
    
    ```
    
    Output:

    ```
    [json.exception.type_error.302] (bytes 92-95) type must be number, but is string
    
    ```

        The output shows the exception with start/end positions only.

??? example "Example: using extended diagnostics with positions enabled in exceptions"

    ```cpp
    #include <iostream>
    
    #define JSON_DIAGNOSTICS 1
    #define JSON_DIAGNOSTIC_POSITIONS 1
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
    /* Demonstration of type error exception with diagnostic positions support enabled */
    int main()
    {
        //Invalid json string - housenumber type must be int instead of string
        const std::string json_invalid_string = R"(
        {
            "address": {
                "street": "Fake Street",
                "housenumber": "1"
            }
        }
        )";
        json j = json::parse(json_invalid_string);
        try
        {
            int housenumber = j["address"]["housenumber"];
            std::cout << housenumber;
        }
        catch (const json::exception& e)
        {
            std::cout << e.what() << '\n';
        }
    }
    
    ```
    
    Output:

    ```
    [json.exception.type_error.302] (/address/housenumber) (bytes 92-95) type must be number, but is string
    
    ```
    
        The output shows the exception with diagnostic path info and start/end positions.

## See also

- [:simple-cmake: JSON_Diagnostic_Positions](../../integration/cmake.md#json_diagnostic_positions) - CMake option to control the macro
- [JSON_DIAGNOSTICS](json_diagnostics.md) - macro to control extended diagnostics

## Version history

- Added in version 3.12.0.
