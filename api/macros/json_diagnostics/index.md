# JSON_DIAGNOSTICS

```
#define JSON_DIAGNOSTICS /* value */
```

This macro enables [extended diagnostics for exception messages](https://json.nlohmann.me/home/exceptions/#extended-diagnostic-messages). Possible values are `1` to enable or `0` to disable (default).

When enabled, exception messages contain a [JSON Pointer](https://json.nlohmann.me/api/json_pointer/json_pointer/index.md) to the JSON value that triggered the exception. Note that enabling this macro increases the size of every JSON value by one pointer and adds some runtime overhead.

## Default definition

The default value is `0` (extended diagnostics are switched off).

```
#define JSON_DIAGNOSTICS 0
```

When the macro is not defined, the library will define it to its default value.

## Notes

ABI compatibility

As of version 3.11.0, this macro is no longer required to be defined consistently throughout a codebase to avoid One Definition Rule (ODR) violations, as the value of this macro is encoded in the namespace, resulting in distinct symbol names.

This allows different parts of a codebase to use different versions or configurations of this library without causing improper behavior.

Where possible, it is still recommended that all code define this the same way for maximum interoperability.

CMake option

Diagnostic messages can also be controlled with the CMake option [`JSON_Diagnostics`](https://json.nlohmann.me/integration/cmake/#json_diagnostics) (`OFF` by default) which defines `JSON_DIAGNOSTICS` accordingly. Note this only applies when building the library from source — see the pre-installed-package caveat on that page.

## Examples

Example 1: default behavior

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    json j;
    j["address"]["street"] = "Fake Street";
    j["address"]["housenumber"] = "12";

    try
    {
        int housenumber = j["address"]["housenumber"];
    }
    catch (const json::exception& e)
    {
        std::cout << e.what() << '\n';
    }
}
```

Output:

```
[json.exception.type_error.302] type must be number, but is string
```

This exception can be hard to debug if storing the value `"12"` and accessing it is further apart.

Example 2: extended diagnostic messages

```
#include <iostream>

# define JSON_DIAGNOSTICS 1
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    json j;
    j["address"]["street"] = "Fake Street";
    j["address"]["housenumber"] = "12";

    try
    {
        int housenumber = j["address"]["housenumber"];
    }
    catch (const json::exception& e)
    {
        std::cout << e.what() << '\n';
    }
}
```

Output:

```
[json.exception.type_error.302] (/address/housenumber) type must be number, but is string
```

Now the exception message contains a JSON Pointer `/address/housenumber` that indicates which value has the wrong type.

Example 3: using only diagnostic positions in exceptions

```
#include <iostream>

#define JSON_DIAGNOSTIC_POSITIONS 1
#include <nlohmann/json.hpp>

using json = nlohmann::json;

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

## See also

- [JSON_Diagnostics](https://json.nlohmann.me/integration/cmake/#json_diagnostics) - CMake option to control the macro
- [JSON_DIAGNOSTIC_POSITIONS](https://json.nlohmann.me/api/macros/json_diagnostic_positions/index.md) - macro to access positions of elements

## Version history

- Added in version 3.10.0.
- As of version 3.11.0, the definition is allowed to vary between translation units.
