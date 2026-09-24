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
    --8<-- "examples/nlohmann_json_namespace_no_version.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/nlohmann_json_namespace_no_version.output"
    ```

## See also

- [`nlohmann` Namespace](../../features/namespace.md)
- [`NLOHMANN_JSON_NAMESPACE`](nlohmann_json_namespace.md)
- [`NLOHMANN_JSON_NAMESPACE_BEGIN, NLOHMANN_JSON_NAMESPACE_END`](nlohmann_json_namespace_begin.md)

## Version history

- Added in version 3.11.2.
