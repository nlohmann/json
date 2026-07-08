# JSON_USE_GLOBAL_UDLS

```
#define JSON_USE_GLOBAL_UDLS /* value */
```

When defined to `1`, the user-defined string literals (UDLs) are placed into the global namespace instead of `nlohmann::literals::json_literals`.

## Default definition

The default value is `1`.

```
#define JSON_USE_GLOBAL_UDLS 1
```

When the macro is not defined, the library will define it to its default value.

## Notes

Future behavior change

The user-defined string literals will be removed from the global namespace in the next major release of the library.

To prepare existing code, define `JSON_USE_GLOBAL_UDLS` to `0` and bring the string literals into scope where needed. Refer to any of the [string literals](#see-also) for details.

CMake option

The placement of user-defined string literals can also be controlled with the CMake option [`JSON_GlobalUDLs`](https://json.nlohmann.me/integration/cmake/#json_globaludls) (`ON` by default) which defines `JSON_USE_GLOBAL_UDLS` accordingly.

## Examples

Example 1: Default behavior

The code below shows the default behavior using the `_json` UDL.

```
#include <nlohmann/json.hpp>

#include <iostream>

int main()
{
    auto j = "42"_json;

    std::cout << j << std::endl;
}
```

Output:

```
42
```

Example 2: Namespaced UDLs

The code below shows how UDLs need to be brought into scope before using `_json` when `JSON_USE_GLOBAL_UDLS` is defined to `0`.

```
#define JSON_USE_GLOBAL_UDLS 0
#include <nlohmann/json.hpp>

#include <iostream>

int main()
{
    // auto j = "42"_json; // This line would fail to compile,
                           // because the UDLs are not in the global namespace

    // Bring the UDLs into scope
    using namespace nlohmann::json_literals;

    auto j = "42"_json;

    std::cout << j << std::endl;
}
```

Output:

```
42
```

## See also

- [`operator""_json`](https://json.nlohmann.me/api/operator_literal_json/index.md)
- [`operator""_json_pointer`](https://json.nlohmann.me/api/operator_literal_json_pointer/index.md)
- [JSON_GlobalUDLs](https://json.nlohmann.me/integration/cmake/#json_globaludls) - CMake option to control the macro

## Version history

- Added in version 3.11.0.
