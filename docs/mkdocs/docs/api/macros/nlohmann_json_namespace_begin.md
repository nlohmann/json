# NLOHMANN_JSON_NAMESPACE_BEGIN, NLOHMANN_JSON_NAMESPACE_END

```cpp
#define NLOHMANN_JSON_NAMESPACE_BEGIN  // (1)
#define NLOHMANN_JSON_NAMESPACE_END    // (2)
```

These macros can be used to open and close the `nlohmann` namespace. They
include an inline namespace used to differentiate symbols when linking multiple
versions (including different ABI-affecting macros) of this library.

1. Opens the namespace.
    ```cpp
    namespace nlohmann
    {
    inline namespace json_v3_11_0
    {
    ```

2. Closes the namespace.
    ```cpp
    }  // namespace nlohmann
    }  // json_v3_11_0
    ```

## Default definition

The default definitions open and close the `nlohmann` as well as an inline
namespace.

When these macros are not defined, the library will define them to their
default definitions.

## See also

- [NLOHMANN_JSON_NAMESPACE](nlohmann_json_namespace.md)

## Version history

- Added in version 3.11.0.
