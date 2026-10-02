# <small>nlohmann::basic_json::</small>parse_event_t

```cpp
enum class parse_event_t : std::uint8_t {
    object_start,
    object_end,
    array_start,
    array_end,
    key,
    value
};
```

The parser callback distinguishes the following events:

- `object_start`: the parser read `{` and started to process a JSON object
- `key`: the parser read a key of a value in an object
- `object_end`: the parser read `}` and finished processing a JSON object
- `array_start`: the parser read `[` and started to process a JSON array
- `array_end`: the parser read `]` and finished processing a JSON array
- `value`: the parser finished reading a JSON value

## Examples

![Example when certain parse events are triggered](../../images/callback_events.png)

??? example

    The following code parses a small JSON text with a parser callback that reports every event together with its
    depth and keeps every value (by always returning `#!cpp true`).

    ```cpp
    --8<-- "examples/parse_event_t.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/parse_event_t.output"
    ```

## See also

- [parser_callback_t](parser_callback_t.md) callback function type for the parser
- [parse](parse.md) deserialize from a compatible input

## Version history

- Added in version 1.0.0.
