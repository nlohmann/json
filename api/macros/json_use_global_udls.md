# JSON_USE_GLOBAL_UDLS

```cpp
#define JSON_USE_GLOBAL_UDLS /* value */
```

When defined to `1`, the user-defined string literals (UDLs) are placed into the global namespace instead of
`nlohmann::literals::json_literals`.

## Default definition

The default value is `1`.

```cpp
#define JSON_USE_GLOBAL_UDLS 1
```

When the macro is not defined, the library will define it to its default value.

## Notes

!!! info "Future behavior change"

    The user-defined string literals will be removed from the global namespace in the next major release of the library.

    To prepare existing code, define `JSON_USE_GLOBAL_UDLS` to `0` and bring the string literals into scope where
    needed. Refer to any of the [string literals](#see-also) for details.

!!! hint "CMake option"

    The placement of user-defined string literals can also be controlled with the CMake option
    [`JSON_GlobalUDLs`](../../integration/cmake.md#json_globaludls) (`ON` by default) which defines
    `JSON_USE_GLOBAL_UDLS` accordingly.

## Examples

??? example "Example 1: Default behavior"

    The code below shows the default behavior using the `_json` UDL.
    
    ```cpp
    #include <nlohmann/json.hpp>
    
    #include <iostream>
    
    int main()
    {
        auto j = "42"_json;
    
        std::cout << j << std::endl;
    }
    ```
    
    Output:
    
    ```json
    42
    ```

??? example "Example 2: Namespaced UDLs"

    The code below shows how UDLs need to be brought into scope before using `_json` when `JSON_USE_GLOBAL_UDLS` is
    defined to `0`.
    
    ```cpp
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
    
    ```json
    42
    ```

## See also

- [`operator""_json`](../operator_literal_json.md)
- [`operator""_json_pointer`](../operator_literal_json_pointer.md)
- [:simple-cmake: JSON_GlobalUDLs](../../integration/cmake.md#json_globaludls) - CMake option to control the macro

## Version history

- Added in version 3.11.0.
