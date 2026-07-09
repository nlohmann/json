# Parser Callbacks

## Overview

With a parser callback function, the result of parsing a JSON text can be influenced. When passed to `parse`, it is called on certain events (passed as `parse_event_t` via parameter `event`) with a set recursion depth `depth` and context JSON value `parsed`. The return value of the callback function is a boolean indicating whether the element that emitted the callback shall be kept or not.

The type of the callback function is:

```
template<typename BasicJsonType>
using parser_callback_t =
    std::function<bool(int depth, parse_event_t event, BasicJsonType& parsed)>;
```

## Callback event types

We distinguish six scenarios (determined by the event type) in which the callback function can be called. The following table describes the values of the parameters `depth`, `event`, and `parsed`.

| parameter `event`             | description                                               | parameter `depth`                         | parameter `parsed`               |
| ----------------------------- | --------------------------------------------------------- | ----------------------------------------- | -------------------------------- |
| `parse_event_t::object_start` | the parser read `{` and started to process a JSON object  | depth of the parent of the JSON object    | a JSON value with type discarded |
| `parse_event_t::key`          | the parser read a key of a value in an object             | depth of the currently parsed JSON object | a JSON string containing the key |
| `parse_event_t::object_end`   | the parser read `}` and finished processing a JSON object | depth of the parent of the JSON object    | the parsed JSON object           |
| `parse_event_t::array_start`  | the parser read `[` and started to process a JSON array   | depth of the parent of the JSON array     | a JSON value with type discarded |
| `parse_event_t::array_end`    | the parser read `]` and finished processing a JSON array  | depth of the parent of the JSON array     | the parsed JSON array            |
| `parse_event_t::value`        | the parser finished reading a JSON value                  | depth of the value                        | the parsed JSON value            |

Example

When parsing the following JSON text,

```
{
    "name": "Berlin",
    "location": [
        52.519444,
        13.406667
    ]
}
```

these calls are made to the callback function:

| event          | depth | parsed                                               |
| -------------- | ----- | ---------------------------------------------------- |
| `object_start` | 0     | *discarded*                                          |
| `key`          | 1     | `"name"`                                             |
| `value`        | 1     | `"Berlin"`                                           |
| `key`          | 1     | `"location"`                                         |
| `array_start`  | 1     | *discarded*                                          |
| `value`        | 2     | `52.519444`                                          |
| `value`        | 2     | `13.406667`                                          |
| `array_end`    | 1     | `[52.519444,13.406667]`                              |
| `object_end`   | 0     | `{"location":[52.519444,13.406667],"name":"Berlin"}` |

## Return value

Discarding a value (i.e., returning `false`) has different effects depending on the context in which the function was called:

- Discarded values in structured types are skipped. That is, the parser will behave as if the discarded value was never read.
- In case a value outside a structured type is skipped, it is replaced with `null`. This case happens if the top-level element is skipped.

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

## Recipe: rejecting duplicate object keys

The JSON specification leaves the handling of objects with repeated keys up to the implementation. As described in [`object_t`](https://json.nlohmann.me/api/basic_json/object_t/#behavior), it is unspecified which value for a repeated key ends up in the resulting `json` value -- once parsing has produced that value, the duplicate is already gone, because object storage maps each key to a single value. If duplicate keys should instead be treated as an error, a parser callback can detect them while the object is still being read, before that ambiguity ever applies.

Example

```
#include <iostream>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

using json = nlohmann::json;

json parse_strict(const std::string& input)
{
    // one key set per nesting depth, reused across sibling objects
    std::vector<std::unordered_set<std::string>> keys;

    auto reject_duplicate_keys = [&](int depth, json::parse_event_t event, json & parsed)
    {
        if (event == json::parse_event_t::object_start)
        {
            // keys of this object are reported at depth+1 (see the event table above)
            const auto child_depth = static_cast<std::size_t>(depth) + 1;
            if (keys.size() <= child_depth)
            {
                keys.resize(child_depth + 1);
            }
            keys[child_depth].clear();
            return true;
        }

        if (event == json::parse_event_t::key)
        {
            auto& seen = keys[static_cast<std::size_t>(depth)];
            const auto& key = parsed.get_ref<const std::string&>();
            if (!seen.insert(key).second)
            {
                throw std::runtime_error("duplicate JSON object key: " + key);
            }
            return true;
        }

        return true;
    };

    return json::parse(input, reject_duplicate_keys);
}

int main()
{
    // parsing succeeds when all keys are unique
    json j = parse_strict(R"({"one": 1, "two": 2})");
    std::cout << j << '\n';

    // parsing throws when a key is repeated
    try
    {
        parse_strict(R"({"one": 1, "one": 2})");
    }
    catch (const std::exception& e)
    {
        std::cout << e.what() << '\n';
    }
}
```

Output:

```
{"one":1,"two":2}
duplicate JSON object key: one
```

This approach has two limitations:

- The depth-indexed bookkeeping must account for the fact that `object_start` reports the depth of the *parent* of the object, while the `key` events inside that object are reported one depth deeper (see the event table above); it is easy to get this off by one for nested objects.
- The thrown exception cannot carry a `parse_error`-style byte offset, because position tracking only exists inside the parser and lexer, not at the callback layer.

For strict validation with precise error positions, implementing a [SAX interface](https://json.nlohmann.me/features/parsing/sax_interface/index.md) instead gives access to the parser's position information directly.
