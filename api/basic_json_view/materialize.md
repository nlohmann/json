# <small>nlohmann::basic_json_view::</small>materialize

```cpp
BasicJsonType materialize() const;
```

Builds the `BasicJsonType` value of this subtree: the value [`BasicJsonType::parse()`](../basic_json/parse.md) would
have produced for the same source text, allocated for the first time by this call.

## Return value

The `BasicJsonType` value of this subtree, or a discarded `BasicJsonType` value (`#!cpp BasicJsonType(value_t::discarded)`)
if the view is [discarded](is_discarded.md).

## Exception safety

Strong guarantee: there are no changes to the view or the document it refers to (nothing about either is mutated by
this function).

## Exceptions

May throw `#!cpp std::bad_alloc` (via `BasicJsonType`'s allocator) if constructing the result fails.

## Complexity

Linear in the size of the subtree.

## Notes

`materialize()` replays the subtree through the same SAX builder [`BasicJsonType::parse()`](../basic_json/parse.md)
uses, so the result matches it exactly — including, for an object, that a repeated key keeps only its
last value. The replay is iterative, so it is not limited by the call stack the way a naive recursive conversion
would be; the JSON nesting depth is limited only by available memory, as for `BasicJsonType::parse()` itself.

Unlike parsing with [`JSON_DIAGNOSTIC_POSITIONS`](../macros/json_diagnostic_positions.md) enabled, the values
produced by `materialize()` do not carry source positions. The index has the start offset of every value, but not the
end of arrays, objects, and escaped strings, which the positions also need.

Calling `materialize()` on the same view repeatedly builds a new, independent `BasicJsonType` value each time; it
never caches the result.

## Examples

??? example

    The example below skips messages that are not useful — a discarded value, or an empty array — using only
    [`is_array()`](is_array.md) and [`empty()`](empty.md), and calls `materialize()` only for the messages that are
    actually used, so no `BasicJsonType` value (and none of its per-element allocations) is ever built for the
    skipped ones.

    ```cpp
    #include <array>
    #include <iostream>
    #include <nlohmann/json_view.hpp>
    
    using nlohmann::json_document;
    
    int main()
    {
        // three incoming messages; skip the ones that are not useful without ever
        // building a nlohmann::json value for them
        json_document heartbeat = json_document::parse("null");
        json_document empty_batch = json_document::parse("[]");
        json_document batch = json_document::parse(R"([{"id": 1}, {"id": 2}, {"id": 3}])");
        std::array<const json_document*, 3> messages = {{&heartbeat, &empty_batch, &batch}};
    
        for (const json_document* d : messages)
        {
            // is_array()/empty() only look at the flat index: a discarded
            // heartbeat or an empty batch is never turned into a nlohmann::json
            // value, so no per-element allocation happens for them
            if (!d->root().is_array() || d->root().empty())
            {
                std::cout << "skipped\n";
                continue;
            }
    
            // materialize() replays the subtree through the same SAX builder
            // basic_json::parse() uses, so the result is exactly what
            // basic_json::parse() would have produced for the same text
            nlohmann::json value = d->root().materialize();
            std::cout << value.dump() << '\n';
        }
    }
    
    ```

    Output:

    ```json
    skipped
    skipped
    [{"id":1},{"id":2},{"id":3}]
    
    ```

## See also

- [`root`](../basic_json_document/root.md) - the view of a document's root value
- [`BasicJsonType::parse`](../basic_json/parse.md) - build a `BasicJsonType` value directly from a JSON text
- [`JSON_DIAGNOSTIC_POSITIONS`](../macros/json_diagnostic_positions.md) - source positions on parsed values (not
  produced by `materialize()`)
- [Zero-copy JSON views](../../features/json_view.md#getting-values-out-without-copying) - when to build a basic_json value from a view

## Version history

- Added in version 3.13.0.
