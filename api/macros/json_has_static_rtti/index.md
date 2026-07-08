# JSON_HAS_STATIC_RTTI

```
#define JSON_HAS_STATIC_RTTI /* value */
```

This macro indicates whether the standard library has any support for RTTI (run time type information). Possible values are `1` when supported or `0` when unsupported.

## Default definition

The default value is detected based on the preprocessor macro `_HAS_STATIC_RTTI`.

When the macro is not defined, the library will define it to its default value.

## Examples

Example

The code below forces the library to enable support for libraries with RTTI dependence:

```
#define JSON_HAS_STATIC_RTTI 1
#include <nlohmann/json.hpp>

...
```

## Version history

- Added in version 3.11.3.
