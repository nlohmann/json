# <small>nlohmann::basic_json::</small>bjdata_version_t

```cpp
enum class bjdata_version_t
{
    draft2,
    draft3,
};
```

This enumeration is used in the [`to_bjdata`](to_bjdata.md) function to choose which draft version of
the BJData specification to encode ND-array extensions for:

draft2
:   encode using the BJData Draft 2 ND-array format

draft3
:   encode using the BJData Draft 3 ND-array format

## Examples

??? example

    The example shows how `bjdata_version_t` selects the BJData draft used by `to_bjdata`.

    ```cpp
    --8<-- "examples/bjdata_version_t.cpp"
    ```

    Output:

    ```
    --8<-- "examples/bjdata_version_t.output"
    ```

## Version history

- Added in version 3.12.0.
