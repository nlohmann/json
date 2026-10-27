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

## See also

- [`operator ValueType`](https://json.nlohmann.me/api/basic_json/operator_ValueType/index.md) - get a value (implicit); on C++17, this macro controls whether `std::any` is excluded from its candidate types
- [Supported Macros](https://json.nlohmann.me/features/macros/index.md) - guide to all supported macros
- [Converting values](https://json.nlohmann.me/features/conversions/index.md) - conversions of values

## Version history

- Added in version 3.11.3.
