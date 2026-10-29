# <small>nlohmann::basic_json::</small>parser_callback_t

```cpp
template<typename BasicJsonType>
using parser_callback_t =
    std::function<bool(int depth, parse_event_t event, BasicJsonType& parsed)>;
```

With a parser callback function, the result of parsing a JSON text can be influenced. When passed to
[`parse`](parse.md), it is called on certain events (passed as [`parse_event_t`](parse_event_t.md) via parameter
`event`) with a set recursion depth `depth` and context JSON value `parsed`. The return value of the callback function
is a boolean indicating whether the element that emitted the callback shall be kept or not.

We distinguish six scenarios (determined by the event type) in which the callback function can be called. The following
table describes the values of the parameters `depth`, `event`, and `parsed`.

| parameter `event`             | description                                               | parameter `depth`                         | parameter `parsed`               |
|-------------------------------|-----------------------------------------------------------|-------------------------------------------|----------------------------------|
| `parse_event_t::object_start` | the parser read `{` and started to process a JSON object  | depth of the parent of the JSON object    | a JSON value with type discarded |
| `parse_event_t::key`          | the parser read a key of a value in an object             | depth of the currently parsed JSON object | a JSON string containing the key |
| `parse_event_t::object_end`   | the parser read `}` and finished processing a JSON object | depth of the parent of the JSON object    | the parsed JSON object           |
| `parse_event_t::array_start`  | the parser read `[` and started to process a JSON array   | depth of the parent of the JSON array     | a JSON value with type discarded |
| `parse_event_t::array_end`    | the parser read `]` and finished processing a JSON array  | depth of the parent of the JSON array     | the parsed JSON array            |
| `parse_event_t::value`        | the parser finished reading a JSON value                  | depth of the value                        | the parsed JSON value            |

<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-fig--cb" viewBox="0 0 480 262" role="img" aria-labelledby="fig-cb-title" xmlns="http://www.w3.org/2000/svg">
<title id="fig-cb-title">Example of the parse events a callback sees for the J&#8203;SON text {&quot;name&quot;: &quot;Berlin&quot;, &quot;location&quot;: [52.519444, 13.406667]}: object_start after the opening brace, key after each key, array_start after the opening bracket, value after each value, array_end after the closing bracket, and object_end after the closing brace. Every array and object also produces a value event when it is complete.</title>
<text class="fg-h" x="16" y="28">J&#8203;SON to parse</text>
<text class="fg-h" x="320" y="28">callback events</text>
<text class="fg-code" x="16" y="74" xml:space="preserve">{</text>
<circle class="cb-os" cx="35.6" cy="69" r="5.5"/>
<text class="fg-code" x="35.2" y="102" xml:space="preserve">&quot;name&quot;</text>
<circle class="cb-k" cx="102.8" cy="97" r="5.5"/>
<text class="fg-code" x="112.8" y="102" xml:space="preserve">: &quot;Berlin&quot;</text>
<circle class="cb-v" cx="218.8" cy="97" r="5.5"/>
<text class="fg-code" x="228.8" y="102" xml:space="preserve">,</text>
<text class="fg-code" x="35.2" y="130" xml:space="preserve">&quot;location&quot;</text>
<circle class="cb-k" cx="141.2" cy="125" r="5.5"/>
<text class="fg-code" x="151.2" y="130" xml:space="preserve">: [</text>
<circle class="cb-as" cx="190" cy="125" r="5.5"/>
<text class="fg-code" x="54.4" y="158" xml:space="preserve">52.519444</text>
<circle class="cb-v" cx="150.8" cy="153" r="5.5"/>
<text class="fg-code" x="160.8" y="158" xml:space="preserve">,</text>
<text class="fg-code" x="54.4" y="186" xml:space="preserve">13.406667</text>
<circle class="cb-v" cx="150.8" cy="181" r="5.5"/>
<text class="fg-code" x="35.2" y="214" xml:space="preserve">]</text>
<circle class="cb-ae" cx="54.8" cy="209" r="5.5"/>
<circle class="cb-v" cx="74.8" cy="209" r="5.5"/>
<text class="fg-code" x="16" y="242" xml:space="preserve">}</text>
<circle class="cb-oe" cx="35.6" cy="237" r="5.5"/>
<circle class="cb-v" cx="55.6" cy="237" r="5.5"/>
<circle class="cb-os" cx="327" cy="69" r="6"/>
<text class="fg-code fg-leg" x="344" y="74">object_start</text>
<circle class="cb-k" cx="327" cy="99" r="6"/>
<text class="fg-code fg-leg" x="344" y="104">key</text>
<circle class="cb-oe" cx="327" cy="129" r="6"/>
<text class="fg-code fg-leg" x="344" y="134">object_end</text>
<circle class="cb-as" cx="327" cy="159" r="6"/>
<text class="fg-code fg-leg" x="344" y="164">array_start</text>
<circle class="cb-ae" cx="327" cy="189" r="6"/>
<text class="fg-code fg-leg" x="344" y="194">array_end</text>
<circle class="cb-v" cx="327" cy="219" r="6"/>
<text class="fg-code fg-leg" x="344" y="224">value</text>
</svg>

</div>

<p class="nj-caption" markdown>Parse events for a small JSON text: each coloured dot marks the position at which the
parser calls the callback, and the legend on the right names the event per colour.</p>

Discarding a value (i.e., returning `#!cpp false`) has different effects depending on the context in which function was
called:

- Discarded values in structured types are skipped. That is, the parser will behave as if the discarded value was never
  read. This holds for every value type and for both kinds of parent: a discarded element is removed from the
  surrounding array, and a discarded member is removed from the surrounding object together with its key.
- Arrays and objects can be discarded either at their `parse_event_t::array_start`/`parse_event_t::object_start` event
  or at their `parse_event_t::array_end`/`parse_event_t::object_end` event, and both remove the whole value. Discarding
  it at the start event also means the callback is called neither for the content of the value nor for its matching end
  event.
- Discarding a `parse_event_t::key` event discards the whole object member. The callback is still called for the
  associated value, but its return value has no further effect.
- In case a value outside a structured type is skipped, it is replaced with `null`. This case happens if the top-level
  element is skipped.

## Parameters

`depth` (in)
:   the depth of the recursion during parsing

`event` (in)
:   an event of type [`parse_event_t`](parse_event_t.md) indicating the context in
    the callback function has been called

`parsed` (in, out)
:    the current intermediate parse result; note that
     writing to this value has no effect for `parse_event_t::key` events

## Return value

Whether the JSON value which called the function during parsing should be kept (`#!cpp true`) or not (`#!cpp false`). In
the latter case, it is skipped completely, or replaced by `null` if it is the top-level value.

## Notes

For a `parse_event_t::key` event, `parsed` holds the decoded object name, with the same guarantees as the `val`
parameter of [`json_sax::key`](../json_sax/key.md#notes): all escape sequences are decoded and `\uXXXX` escapes are
stored as UTF-8, so different spellings of the same name yield identical strings; the name is validated completely
before the callback is called, so a name with an invalid escape sequence or ill-formed UTF-8 causes a parse error and
no `key` event; no Unicode normalization or case conversion is applied; and a name that occurs several times in the
same object yields one `key` event per occurrence.

## Examples

??? example "Example: skip an object key while parsing"

    The example below demonstrates the `parse()` function with
    and without callback function.

    ```cpp
    #include <iostream>
    #include <iomanip>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
    int main()
    {
        // a JSON text
        const auto* text = R"(
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
    
    ```json
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

??? example "Example: how discarded values are removed"

    The example below shows where discarded values are removed. The array and the number are discarded in different
    ways, but in each case the parse result contains neither the value nor its key.

    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
    int main()
    {
        // a JSON text with an array and a number inside an object
        const auto* text = R"({"IDs": [116, 943], "Width": 800})";
    
        // discard the array when the parser reads its opening bracket
        json j_array_start = json::parse(text, [](int /*depth*/, json::parse_event_t event, json& /*parsed*/)
        {
            return event != json::parse_event_t::array_start;
        });
    
        // discard the same array when the parser reads its closing bracket
        json j_array_end = json::parse(text, [](int /*depth*/, json::parse_event_t event, json& /*parsed*/)
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
        json j_root = json::parse(text, [](int /*depth*/, json::parse_event_t event, json& /*parsed*/)
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

    ```json
    {"Width":800}
    {"Width":800}
    {"IDs":[116,943]}
    {"IDs":[116,943]}
    null
    
    ```

## See also

- [`parse`](parse.md) - deserialize from a compatible input
- [`parse_event_t`](parse_event_t.md) - enumeration of parser events
- [Parser Callbacks](../../features/parsing/parser_callbacks.md) - filter or inspect values while parsing

## Version history

- Added in version 1.0.0.
- Fixed in version 3.13.0 to also remove discarded values from a parent object; before, discarding an array or a value
  stored under an object key left a discarded member behind, which made the parse result serialize to invalid JSON.
- Fixed in version 3.13.0 so that discarding an array or object at its start event also hides its content from the
  callback, as documented above; before, the callback was still called for the content, and the key of every member of
  a discarded object was kept in memory until the parse ended.
