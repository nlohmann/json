# nlohmann::basic_json::parse_event_t

```
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

Example

The following code parses a small JSON text with a parser callback that reports every event together with its depth and keeps every value (by always returning `true`).

```
#include <iostream>
#include <string>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// translate a parse_event_t to a human-readable name
std::string event_name(json::parse_event_t event)
{
    switch (event)
    {
        case json::parse_event_t::object_start:
            return "object_start";
        case json::parse_event_t::object_end:
            return "object_end";
        case json::parse_event_t::array_start:
            return "array_start";
        case json::parse_event_t::array_end:
            return "array_end";
        case json::parse_event_t::key:
            return "key";
        case json::parse_event_t::value:
            return "value";
        default:
            return "unknown";
    }
}

int main()
{
    // a small JSON text
    auto text = R"({"pi": 3.141, "numbers": [1, 2]})";

    // parse the text and report every event together with its depth;
    // returning true keeps every value unchanged
    json j = json::parse(text, [](int depth, json::parse_event_t event, json& /*parsed*/)
    {
        std::cout << depth << " " << event_name(event) << '\n';
        return true;
    });

    // the callback did not change anything, so the parsed value is unaffected
    std::cout << j << '\n';
}
```

Output:

```
0 object_start
1 key
1 value
1 key
1 array_start
2 value
2 value
1 array_end
0 object_end
{"numbers":[1,2],"pi":3.141}
```

## See also

- [parser_callback_t](https://json.nlohmann.me/api/basic_json/parser_callback_t/index.md) callback function type for the parser
- [parse](https://json.nlohmann.me/api/basic_json/parse/index.md) deserialize from a compatible input

## Version history

- Added in version 1.0.0.
