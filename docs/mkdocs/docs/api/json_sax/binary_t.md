# <small>nlohmann::json_sax::</small>binary_t

```cpp
using binary_t = typename BasicJsonType::binary_t;
```

The type used by the [`binary`](binary.md) callback for JSON binary values, forwarded from the
`BasicJsonType` template parameter.

See [`basic_json::binary_t`](../basic_json/binary_t.md) for more information.

## Examples

??? example

    The example shows the type `binary_t` and its relation to `basic_json::binary_t`.

    ```cpp
    --8<-- "examples/json_sax__binary_t.cpp"
    ```

    Output:

    ```
    --8<-- "examples/json_sax__binary_t.output"
    ```

## Version history

- Added in version 3.8.0.
