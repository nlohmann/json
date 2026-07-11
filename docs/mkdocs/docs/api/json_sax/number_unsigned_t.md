# <small>nlohmann::json_sax::</small>number_unsigned_t

```cpp
using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
```

The type used by the [`number_unsigned`](number_unsigned.md) callback for JSON unsigned integer numbers,
forwarded from the `BasicJsonType` template parameter.

See [`basic_json::number_unsigned_t`](../basic_json/number_unsigned_t.md) for more information.

## Examples

??? example

    The example shows the type `number_unsigned_t` and its relation to `basic_json::number_unsigned_t`.

    ```cpp
    --8<-- "examples/json_sax__number_unsigned_t.cpp"
    ```

    Output:

    ```
    --8<-- "examples/json_sax__number_unsigned_t.output"
    ```

## Version history

- Added in version 3.2.0.
