# JSON_HAS_STD_FORMAT

```
#define JSON_HAS_STD_FORMAT /* value */
```

This macro indicates whether the standard library has support for `std::format`/`std::formatter` (that is, the `<format>` header). Possible values are `1` when supported or `0` when unsupported.

## Default definition

The default value is detected based on the preprocessor macros `JSON_HAS_CPP_20` and `__cpp_lib_format`.

When the macro is not defined, the library will define it to its default value.

## Notes

Enabled functionality

When this macro evaluates to `1`, the library provides a [`std::formatter<basic_json>`](https://json.nlohmann.me/api/basic_json/std_formatter/index.md) specialization so JSON values can be used directly with `std::format`.

## Examples

Example

The code below forces the library to disable support for `std::format`, even if the standard library would otherwise support it:

```
#define JSON_HAS_STD_FORMAT 0
#include <nlohmann/json.hpp>

...
```

## Version history

- Added in version 3.13.0.
