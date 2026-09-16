# <small>nlohmann::json_sax::</small>number_float_t

```cpp
using number_float_t = typename BasicJsonType::number_float_t;
```

The type used by the [`number_float`](number_float.md) callback for JSON floating-point numbers,
forwarded from the `BasicJsonType` template parameter.

See [`basic_json::number_float_t`](../basic_json/number_float_t.md) for more information.

## Examples

??? example

    The example shows the type `number_float_t` and its relation to `basic_json::number_float_t`.

    ```cpp
    --8<-- "examples/json_sax__number_float_t.cpp"
    ```

    Output:

    ```
    --8<-- "examples/json_sax__number_float_t.output"
    ```

## Version history

- Added in version 3.2.0.
