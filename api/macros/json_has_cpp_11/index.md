# JSON_HAS_CPP_11, JSON_HAS_CPP_14, JSON_HAS_CPP_17, JSON_HAS_CPP_20, JSON_HAS_CPP_23, JSON_HAS_CPP_26

```
#define JSON_HAS_CPP_11
#define JSON_HAS_CPP_14
#define JSON_HAS_CPP_17
#define JSON_HAS_CPP_20
#define JSON_HAS_CPP_23
#define JSON_HAS_CPP_26
```

The library targets C++11, but also supports some features introduced in later C++ versions (e.g., `std::string_view` support for C++17). For these new features, the library implements some preprocessor checks to determine the C++ standard. By defining any of these symbols, the internal check is overridden and the provided C++ version is unconditionally assumed. This can be helpful for compilers that only implement parts of the standard and would be detected incorrectly.

## Default definition

The default value is detected based on preprocessor macros such as `__cplusplus`, `_HAS_CXX17`, or `_MSVC_LANG`.

## Notes

- When the C++ standard is detected automatically, `JSON_HAS_CPP_11` is always defined. When you override the detection by defining one of these macros manually, the automatic detection is skipped entirely, so you should define all applicable macros (including `JSON_HAS_CPP_11`) yourself.
- All macros are undefined outside the library.

## Examples

Example

The code below forces the library to use the C++14 standard:

```
#define JSON_HAS_CPP_14 1
#include <nlohmann/json.hpp>

...
```

## See also

- [JSON_HAS_FILESYSTEM / JSON_HAS_EXPERIMENTAL_FILESYSTEM](https://json.nlohmann.me/api/macros/json_has_filesystem/index.md) - control `std::filesystem` support
- [JSON_HAS_RANGES](https://json.nlohmann.me/api/macros/json_has_ranges/index.md) - control `std::ranges` support
- [JSON_HAS_THREE_WAY_COMPARISON](https://json.nlohmann.me/api/macros/json_has_three_way_comparison/index.md) - control 3-way comparison support
- [JSON_HAS_STD_FORMAT](https://json.nlohmann.me/api/macros/json_has_std_format/index.md) - control `std::format`/`std::formatter` support

## Version history

- Added in version 3.10.5.
- Added `JSON_HAS_CPP_23` in version 3.12.0.
- Added `JSON_HAS_CPP_26` in version 3.13.0 unreleased.
