# nlohmann::basic_json::parser_callback_t

```
template<typename BasicJsonType>
using parser_callback_t =
    std::function<bool(int depth, parse_event_t event, BasicJsonType& parsed)>;
```

With a parser callback function, the result of parsing a JSON text can be influenced. When passed to [`parse`](https://json.nlohmann.me/api/basic_json/parse/index.md), it is called on certain events (passed as [`parse_event_t`](https://json.nlohmann.me/api/basic_json/parse_event_t/index.md) via parameter `event`) with a set recursion depth `depth` and context JSON value `parsed`. The return value of the callback function is a boolean indicating whether the element that emitted the callback shall be kept or not.

We distinguish six scenarios (determined by the event type) in which the callback function can be called. The following table describes the values of the parameters `depth`, `event`, and `parsed`.

| parameter `event`             | description                                               | parameter `depth`                         | parameter `parsed`               |
| ----------------------------- | --------------------------------------------------------- | ----------------------------------------- | -------------------------------- |
| `parse_event_t::object_start` | the parser read `{` and started to process a JSON object  | depth of the parent of the JSON object    | a JSON value with type discarded |
| `parse_event_t::key`          | the parser read a key of a value in an object             | depth of the currently parsed JSON object | a JSON string containing the key |
| `parse_event_t::object_end`   | the parser read `}` and finished processing a JSON object | depth of the parent of the JSON object    | the parsed JSON object           |
| `parse_event_t::array_start`  | the parser read `[` and started to process a JSON array   | depth of the parent of the JSON array     | a JSON value with type discarded |
| `parse_event_t::array_end`    | the parser read `]` and finished processing a JSON array  | depth of the parent of the JSON array     | the parsed JSON array            |
| `parse_event_t::value`        | the parser finished reading a JSON value                  | depth of the value                        | the parsed JSON value            |

Discarding a value (i.e., returning `false`) has different effects depending on the context in which function was called:

- Discarded values in structured types are skipped. That is, the parser will behave as if the discarded value was never read. This holds for every value type and for both kinds of parent: a discarded element is removed from the surrounding array, and a discarded member is removed from the surrounding object together with its key.
- Arrays and objects can be discarded either at their `parse_event_t::array_start`/`parse_event_t::object_start` event or at their `parse_event_t::array_end`/`parse_event_t::object_end` event, and both remove the whole value. Discarding it at the start event also means the callback is called neither for the content of the value nor for its matching end event.
- Discarding a `parse_event_t::key` event discards the whole object member. The callback is still called for the associated value, but its return value has no further effect.
- In case a value outside a structured type is skipped, it is replaced with `null`. This case happens if the top-level element is skipped.

## Parameters

`depth` (in) : the depth of the recursion during parsing

`event` (in) : an event of type [`parse_event_t`](https://json.nlohmann.me/api/basic_json/parse_event_t/index.md) indicating the context in the callback function has been called

`parsed` (in, out) : the current intermediate parse result; note that writing to this value has no effect for `parse_event_t::key` events

## Return value

Whether the JSON value which called the function during parsing should be kept (`true`) or not (`false`). In the latter case, it is skipped completely, or replaced by `null` if it is the top-level value.

## Examples

Example

The example below demonstrates the `parse()` function with and without callback function.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // a JSON text
    auto text = R"(
    {
        "Image": {
            "Width":  800,
            "Height": 600,
            "Title":  "View from 15th Floor",
            "Thumbnail": {
                "Url":    "http://www.example.com/image/481989943",
                "Height": 125,
                "Width":  100
            },
            "Animated" : false,
            "IDs": [116, 943, 234, 38793]
        }
    }
    )";

    // parse and serialize JSON
    json j_complete = json::parse(text);
    std::cout << std::setw(4) << j_complete << "\n\n";

    // define parser callback
    json::parser_callback_t cb = [](int depth, json::parse_event_t event, json & parsed)
    {
        // skip object elements with key "Thumbnail"
        if (event == json::parse_event_t::key and parsed == json("Thumbnail"))
        {
            return false;
        }
        else
        {
            return true;
        }
    };

    // parse (with callback) and serialize JSON
    json j_filtered = json::parse(text, cb);
    std::cout << std::setw(4) << j_filtered << '\n';
}
```

Output:

```
{
    "Image": {
        "Animated": false,
        "Height": 600,
        "IDs": [
            116,
            943,
            234,
            38793
        ],
        "Thumbnail": {
            "Height": 125,
            "Url": "http://www.example.com/image/481989943",
            "Width": 100
        },
        "Title": "View from 15th Floor",
        "Width": 800
    }
}

{
    "Image": {
        "Animated": false,
        "Height": 600,
        "IDs": [
            116,
            943,
            234,
            38793
        ],
        "Title": "View from 15th Floor",
        "Width": 800
    }
}
```

Example

The example below shows where discarded values are removed. The array and the number are discarded in different ways, but in each case the parse result contains neither the value nor its key.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // a JSON text with an array and a number inside an object
    auto text = R"({"IDs": [116, 943], "Width": 800})";

    // discard the array when the parser reads its opening bracket
    json j_array_start = json::parse(text, [](int /*depth*/, json::parse_event_t event, json & /*parsed*/)
    {
        return event != json::parse_event_t::array_start;
    });

    // discard the same array when the parser reads its closing bracket
    json j_array_end = json::parse(text, [](int /*depth*/, json::parse_event_t event, json & /*parsed*/)
    {
        return event != json::parse_event_t::array_end;
    });

    // discard the number, but keep its key
    json j_value = json::parse(text, [](int /*depth*/, json::parse_event_t event, json & parsed)
    {
        return !(event == json::parse_event_t::value && parsed == json(800));
    });

    // discard the key of the number
    json j_key = json::parse(text, [](int /*depth*/, json::parse_event_t event, json & parsed)
    {
        return !(event == json::parse_event_t::key && parsed == json("Width"));
    });

    // discard the top-level object
    json j_root = json::parse(text, [](int /*depth*/, json::parse_event_t event, json & /*parsed*/)
    {
        return event != json::parse_event_t::object_end;
    });

    // in every case, the discarded value is removed together with its key
    std::cout << j_array_start << '\n'
              << j_array_end << '\n'
              << j_value << '\n'
              << j_key << '\n'
              << j_root << '\n';
}
```

Output:

```
{"Width":800}
{"Width":800}
{"IDs":[116,943]}
{"IDs":[116,943]}
null
```

## See also

- [parse](https://json.nlohmann.me/api/basic_json/parse/index.md) deserialize from a compatible input
- [parse_event_t](https://json.nlohmann.me/api/basic_json/parse_event_t/index.md) enumeration of parser events

## Version history

- Added in version 1.0.0.
- Fixed in version 3.13.0 to also remove discarded values from a parent object; before, discarding an array or a value stored under an object key left a discarded member behind, which made the parse result serialize to invalid JSON.
