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
    --8<-- "examples/nlohmann_json_namespace.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/nlohmann_json_namespace.output"
    ```

## See also

- [`NLOHMANN_JSON_NAMESPACE_BEGIN, NLOHMANN_JSON_NAMESPACE_END`](nlohmann_json_namespace_begin.md)
- [`NLOHMANN_JSON_NAMESPACE_NO_VERSION`](nlohmann_json_namespace_no_version.md)

## Version history

- Added in version 3.11.0. Changed inline namespace name in version 3.11.2.
