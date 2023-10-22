# <small>nlohmann::position_t::</small>chars_read_total

```cpp
std::size_t chars_read_total;
```

The total number of characters read.

## Examples

??? example

    The example below shows a SAX receiving the element bounds as `nlohmann::position_t` and
    storing this location information in each json node using a [base class](../basic_json/json_base_class_t.md) for `nlohmann::json` as customization point.

    ```cpp
    --8<-- "examples/sax_parse_with_src_location_in_json.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/sax_parse_with_src_location_in_json.output"
    ```

## Version history

- Moved from namespace `nlohmann::detail` to `nlohmann` in version ???.???.???.
