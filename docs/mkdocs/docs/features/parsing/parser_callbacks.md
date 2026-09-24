# Parser Callbacks

## Overview

With a parser callback function, the result of parsing a JSON text can be influenced. When passed to `parse`, it is
called on certain events (passed as `parse_event_t` via parameter `event`) with a set recursion depth `depth` and
context JSON value `parsed`. The return value of the callback function is a boolean indicating whether the element that
emitted the callback shall be kept or not.

The type of the callback function is:

```cpp
template<typename BasicJsonType>
using parser_callback_t =
    std::function<bool(int depth, parse_event_t event, BasicJsonType& parsed)>;
```


## Callback event types

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

??? example

    When parsing the following JSON text,
    
    ```json
    {
        "name": "Berlin",
        "location": [
            52.519444,
            13.406667
        ]
    }
    ```
    
    these calls are made to the callback function:
    
    | event          | depth | parsed |
    | -------------- | ----- | ------ |
    | `object_start` | 0     | *discarded* |
    | `key`          | 1     | `#!json "name"` |
    | `value`        | 1     | `#!json "Berlin"` |
    | `key`          | 1     | `#!json "location"` |
    | `array_start`  | 1     | *discarded* |
    | `value`        | 2     | `#!json 52.519444` |
    | `value`        | 2     | `#!json 13.406667` |
    | `array_end`    | 1     | `#!json [52.519444,13.406667]` |
    | `object_end`   | 0     | `#!json {"location":[52.519444,13.406667],"name":"Berlin"}` |

!!! note "No built-in nesting depth limit"

    The library has no built-in limit on recursion/nesting depth while parsing. A parser callback can only
    *discard* content it has already parsed (by returning `#!c false`); it cannot make parsing fail once a
    nesting limit is exceeded partway through reading a deeply nested value. If you need to reject over-deep
    untrusted input outright, track `depth` in a callback and `throw` from it once your limit is exceeded (a
    thrown exception propagates out of `parse()` as usual).

## Return value

Discarding a value (i.e., returning `#!c false`) has different effects depending on the context in which the function
was called:

- Discarded values in structured types are skipped. That is, the parser will behave as if the discarded value was never
  read.
- In case a value outside a structured type is skipped, it is replaced with `#!json null`. This case happens if the
  top-level element is skipped.

??? example

    The example below demonstrates the `parse()` function with and without callback function.

    ```cpp
    --8<-- "examples/parse__string__parser_callback_t.cpp"
    ```
    
    Output:

    ```json
    --8<-- "examples/parse__string__parser_callback_t.output"
    ```

## Recipe: rejecting duplicate object keys

The JSON specification leaves the handling of objects with repeated keys up to the implementation. As described in
[`object_t`](../../api/basic_json/object_t.md#behavior), it is unspecified which value for a repeated key ends up in
the resulting `#!c json` value -- once parsing has produced that value, the duplicate is already gone, because object
storage maps each key to a single value. If duplicate keys should instead be treated as an error, a parser callback
can detect them while the object is still being read, before that ambiguity ever applies.

??? example

    ```cpp
    --8<-- "examples/reject_duplicate_keys.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/reject_duplicate_keys.output"
    ```

This approach has two limitations:

- The depth-indexed bookkeeping must account for the fact that `object_start` reports the depth of the *parent* of
  the object, while the `key` events inside that object are reported one depth deeper (see the event table above);
  it is easy to get this off by one for nested objects.
- The thrown exception cannot carry a `parse_error`-style byte offset, because position tracking only exists inside
  the parser and lexer, not at the callback layer.

For strict validation with precise error positions, implementing a [SAX interface](sax_interface.md) instead gives
access to the parser's position information directly.

## Recipe: streaming a large homogeneous array

A common use case is a huge top-level array of many similarly-shaped objects, too large to hold entirely in
memory as a `#!c json` value. A parser callback can hand off each completed element to a user function and then
discard it, so memory usage stays bounded by a single element (plus the not-yet-parsed tail of the input) rather
than the whole document. Since the top-level array's `array_start`/`array_end` are reported at `depth == 0` (its
parent is the document root), the object elements it contains are reported at `depth == 1`:

??? example

    ```cpp
    std::ifstream input("large_array.json");

    auto callback = [](int depth, json::parse_event_t event, json& parsed) -> bool {
        if (depth == 1 && event == json::parse_event_t::object_end) {
            handle_element(parsed); // process the element, e.g. write it elsewhere
            return false;           // discard it -- frees its memory before the next one is parsed
        }
        return true; // keep everything else, including the (by then empty) top-level array
    };

    json::parse(input, callback);
    ```

If the array's elements are scalars or nested arrays instead of objects, check for `parse_event_t::value` or
`parse_event_t::array_end` at `depth == 1` instead. The same approach works for a top-level *object* of many
homogeneous values by checking `object_end`/`value` events at `depth == 1` there too.

## Recipe: max nesting depth via a callback

Since there is no built-in nesting-depth limit (see the note above), a callback can enforce one manually by
tracking the maximum `depth` seen and throwing once it is exceeded:

??? example

    ```cpp
    constexpr int max_depth = 32;

    auto callback = [](int depth, json::parse_event_t /*event*/, json& /*parsed*/) -> bool {
        if (depth > max_depth) {
            throw std::runtime_error("maximum nesting depth exceeded");
        }
        return true;
    };

    json::parse(input, callback);
    ```
