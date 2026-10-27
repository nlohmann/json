# NLOHMANN_JSON_NAMESPACE

```cpp
#define NLOHMANN_JSON_NAMESPACE /* value */
```

This macro evaluates to the full name of the `nlohmann` namespace.

## Default definition

The default value consists of the root namespace (`nlohmann`) and an inline ABI namespace. See
[`nlohmann` Namespace](../../features/namespace.md#structure) for details.

When the macro is not defined, the library will define it to its default value. Overriding this value has no effect on
the library.

## Examples

??? example

    The example shows how to use `NLOHMANN_JSON_NAMESPACE` instead of just `nlohmann`, as well as how to output the value
    of `NLOHMANN_JSON_NAMESPACE`.

    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    // possible use case: use NLOHMANN_JSON_NAMESPACE instead of nlohmann
    using NLOHMANN_JSON_NAMESPACE::json;
    
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
    nlohmann::json_abi_v3_12_0
    
    ```

## See also

- [`NLOHMANN_JSON_NAMESPACE_BEGIN, NLOHMANN_JSON_NAMESPACE_END`](nlohmann_json_namespace_begin.md) - macros to open and
  close the library namespace
- [`NLOHMANN_JSON_NAMESPACE_NO_VERSION`](nlohmann_json_namespace_no_version.md) - disable the inline versioned namespace
- [Supported Macros](../../features/macros.md) - guide to all supported macros
- [`nlohmann` Namespace](../../features/namespace.md) - the library namespace

## Version history

- Added in version 3.11.0. Changed inline namespace name in version 3.11.2. Added the ABI tag `_dp` in
  version 3.12.0, and the ABI tags `_bics`, `_psp`, `_snul`, `_sbu8`, `_ekmo`, `_dsbs`, `_dufio`, and `_ns` in
  version 3.13.0; see
  [`nlohmann` Namespace](../../features/namespace.md#structure).
