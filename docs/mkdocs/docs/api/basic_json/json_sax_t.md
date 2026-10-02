# <small>nlohmann::basic_json::</small>json_sax_t

```cpp
using json_sax_t = json_sax<basic_json>;
```

The [`json_sax`](../json_sax/index.md) interface bound to this `basic_json` specialization, i.e. with
`BasicJsonType` fixed to `basic_json`. Used as the SAX interface type by [`sax_parse`](sax_parse.md) and
other SAX-based parsing functions.

See [`nlohmann::json_sax`](../json_sax/index.md) for more information.

## Examples

??? example

    The example shows the type `json_sax_t`.

    ```cpp
    --8<-- "examples/json_sax_t.cpp"
    ```

    Output:

    ```
    --8<-- "examples/json_sax_t.output"
    ```

## Version history

- Added in version 3.2.0.
