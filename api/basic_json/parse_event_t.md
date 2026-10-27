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

<p class="nj-caption" markdown>Each coloured dot marks where the parser reports a `parse_event_t` event while reading
the JSON text on the left; the legend on the right names the event per colour.</p>

??? example

    The following code parses a small JSON text with a parser callback that reports every event together with its
    depth and keeps every value (by always returning `#!cpp true`).

    ```cpp
    #include <iostream>
    #include <string>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
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
        const auto* text = R"({"pi": 3.141, "numbers": [1, 2]})";
    
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

    ```json
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

- [`parser_callback_t`](parser_callback_t.md) - callback function type for the parser
- [`parse`](parse.md) - deserialize from a compatible input
- [Parser Callbacks](../../features/parsing/parser_callbacks.md) - filter or inspect values while parsing

## Version history

- Added in version 1.0.0.
