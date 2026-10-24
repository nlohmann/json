# <small>nlohmann::json_sax::</small>number_integer_t

```cpp
using number_integer_t = typename BasicJsonType::number_integer_t;
```

The type used by the [`number_integer`](number_integer.md) callback for JSON integer numbers, forwarded
from the `BasicJsonType` template parameter.

See [`basic_json::number_integer_t`](../basic_json/number_integer_t.md) for more information.

## Examples

??? example

    The example shows the type `number_integer_t` and its relation to `basic_json::number_integer_t`.

    ```cpp
    --8<-- "examples/json_sax__number_integer_t.cpp"
    ```

    Output:

    ```
    --8<-- "examples/json_sax__number_integer_t.output"
    ```

## Version history

- Added in version 3.2.0.
