# JSON_SKIP_UNSUPPORTED_COMPILER_CHECK

```
#define JSON_SKIP_UNSUPPORTED_COMPILER_CHECK
```

When defined, the library will not create a compile error when a known unsupported compiler is detected. This allows using the library with compilers that do not fully support C++11 and may only work if unsupported features are not used.

## Default definition

By default, the macro is not defined.

```
#undef JSON_SKIP_UNSUPPORTED_COMPILER_CHECK
```

## Examples

Example

The code below switches off the check whether the compiler is supported.

```
#define JSON_SKIP_UNSUPPORTED_COMPILER_CHECK 1
#include <nlohmann/json.hpp>

...
```

## See also

- [`JSON_HAS_CPP_11` / `JSON_HAS_CPP_14` / `JSON_HAS_CPP_17` / `JSON_HAS_CPP_20` / `JSON_HAS_CPP_23` / `JSON_HAS_CPP_26`](https://json.nlohmann.me/api/macros/json_has_cpp_11/index.md) - set supported C++ standard
- [Supported Macros](https://json.nlohmann.me/features/macros/index.md) - guide to all supported macros
- [Integration](https://json.nlohmann.me/integration/index.md) - integrate the library

## Version history

- Added in version 3.2.0.
