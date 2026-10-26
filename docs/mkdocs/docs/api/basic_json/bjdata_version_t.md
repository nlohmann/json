# <small>nlohmann::basic_json::</small>bjdata_version_t

```cpp
enum class bjdata_version_t
{
    draft2,
    draft3
};
```

This enumeration is used in [`to_bjdata`](to_bjdata.md) to choose the version of the BJData specification to write:

draft2
:   BJData Draft 2 (the default). Binary values are written as arrays of `U` integers, and ND-arrays with
    `"_ArrayType_": "byte"` are written as regular objects, since the `B` marker is not part of Draft 2.

draft3
:   BJData Draft 3. Binary values are written as `B` elements: as an optimized binary array (`[$B#`) if both `use_size`
    and `use_type` are set, and as an array of `B`-prefixed elements otherwise. ND-arrays with
    `"_ArrayType_": "byte"` are written as packed arrays (`[$B#[...]`).

Only the writer is affected by the version. [`from_bjdata`](from_bjdata.md) reads the markers of both drafts.

## Examples

??? example

    The example below shows how the different values of the `bjdata_version_t` influence the serialization of a binary
    value with [`to_bjdata`](to_bjdata.md).

    ```cpp
    --8<-- "examples/bjdata_version_t.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/bjdata_version_t.output"
    ```

## See also

- [to_bjdata](to_bjdata.md) serializes a JSON value to BJData
- [BJData](../../features/binary_formats/bjdata.md) - the article on the BJData format

## Version history

- Added in version 3.12.0.
