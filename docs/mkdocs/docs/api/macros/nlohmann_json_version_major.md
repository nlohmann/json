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
    --8<-- "examples/nlohmann_json_version.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/nlohmann_json_version.output"
    ```

## See also

- [meta](../basic_json/meta.md) - returns version information on the library
- [JSON_SKIP_LIBRARY_VERSION_CHECK](json_skip_library_version_check.md) - skip library version check

## Version history

- Added in version 3.1.0.
