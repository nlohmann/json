# NLOHMANN_JSON_VERSION_MAJOR, NLOHMANN_JSON_VERSION_MINOR, NLOHMANN_JSON_VERSION_PATCH

```cpp
#define NLOHMANN_JSON_VERSION_MAJOR /* value */
#define NLOHMANN_JSON_VERSION_MINOR /* value */
#define NLOHMANN_JSON_VERSION_PATCH /* value */
```

These macros are defined by the library and contain the version numbers according to
[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## Default definition

The macros are defined according to the current library version.

## Examples

??? example

    The example below shows how `NLOHMANN_JSON_VERSION_MAJOR`, `NLOHMANN_JSON_VERSION_MINOR`, and
    `NLOHMANN_JSON_VERSION_PATCH` are defined by the library.

    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
    int main()
    {
        std::cout << "JSON for Modern C++ version "
                  << NLOHMANN_JSON_VERSION_MAJOR << "."
                  << NLOHMANN_JSON_VERSION_MINOR << "."
                  << NLOHMANN_JSON_VERSION_PATCH << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    JSON for Modern C++ version 3.12.0
    
    ```

## See also

- [`meta`](../basic_json/meta.md) - returns version information on the library
- [`JSON_SKIP_LIBRARY_VERSION_CHECK`](json_skip_library_version_check.md) - skip library version check
- [Supported Macros](../../features/macros.md) - guide to all supported macros
- [Integration](../../integration/index.md) - integrate the library

## Version history

- Added in version 3.1.0.
