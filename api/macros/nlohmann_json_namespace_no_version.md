# NLOHMANN_JSON_NAMESPACE_NO_VERSION

```cpp
#define NLOHMANN_JSON_NAMESPACE_NO_VERSION /* value */
```

If defined to `1`, the version component is omitted from the inline namespace. See
[`nlohmann` Namespace](../../features/namespace.md#structure) for details.

## Default definition

The default value is `0`.

```cpp
#define NLOHMANN_JSON_NAMESPACE_NO_VERSION 0
```

When the macro is not defined, the library will define it to its default value.

## Examples

??? example

    The example shows how to use `NLOHMANN_JSON_NAMESPACE_NO_VERSION` to disable the version component of the inline
    namespace.
    
    ```cpp
    #include <iostream>
    
    #define NLOHMANN_JSON_NAMESPACE_NO_VERSION 1
    #include <nlohmann/json.hpp>
    
    // macro needed to output the NLOHMANN_JSON_NAMESPACE as string literal
    #define Q(x) #x
    #define QUOTE(x) Q(x)
    
    int main()
    {
        std::cout << QUOTE(NLOHMANN_JSON_NAMESPACE) << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    nlohmann::json_abi
    
    ```

## See also

- [`nlohmann` Namespace](../../features/namespace.md) - how the library's namespace is defined and versioned
- [`NLOHMANN_JSON_NAMESPACE`](nlohmann_json_namespace.md) - macro expanding to the library namespace
- [`NLOHMANN_JSON_NAMESPACE_BEGIN, NLOHMANN_JSON_NAMESPACE_END`](nlohmann_json_namespace_begin.md) - macros to open and
  close the library namespace
- [Supported Macros](../../features/macros.md) - guide to all supported macros

## Version history

- Added in version 3.11.2.
