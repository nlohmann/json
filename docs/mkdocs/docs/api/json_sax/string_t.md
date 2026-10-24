# <small>nlohmann::json_sax::</small>string_t

```cpp
using string_t = typename BasicJsonType::string_t;
```

The type used by the [`string`](string.md) and [`key`](key.md) callbacks for JSON strings and object
keys, forwarded from the `BasicJsonType` template parameter.

See [`basic_json::string_t`](../basic_json/string_t.md) for more information.

## Examples

??? example

    The example shows the type `string_t` and its relation to `basic_json::string_t`.

    ```cpp
    --8<-- "examples/json_sax__string_t.cpp"
    ```

    Output:

    ```
    --8<-- "examples/json_sax__string_t.output"
    ```

## Version history

- Added in version 3.2.0.
