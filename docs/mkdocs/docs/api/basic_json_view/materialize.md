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

Strong guarantee: if an exception is thrown, there are no changes to the view or the document it refers to (nothing
about either is mutated by this function).

## Exceptions

May throw `#!cpp std::bad_alloc` (via `BasicJsonType`'s allocator) if constructing the result fails.

## Complexity

Linear in the size of the subtree.

## Notes

`materialize()` replays the subtree through the same SAX builder [`BasicJsonType::parse()`](../basic_json/parse.md)
uses internally, so the result matches it exactly -- including, for an object, that a repeated key keeps only its
last value. The replay is iterative, so it is not limited by the call stack the way a naive recursive conversion
would be; the JSON nesting depth is limited only by available memory, as for `BasicJsonType::parse()` itself.

Unlike parsing with [`JSON_DIAGNOSTIC_POSITIONS`](../macros/json_diagnostic_positions.md) enabled, the values
produced by `materialize()` do not carry source positions: there is no lexer run during the replay to record them.

Calling `materialize()` on the same view repeatedly builds a new, independent `BasicJsonType` value each time; it
never caches the result.

## Examples

??? example

    The example below skips messages that are not useful -- a discarded value, or an empty array -- using only
    [`is_array()`](is_array.md) and [`empty()`](empty.md), and calls `materialize()` only for the messages that are
    actually used, so no `BasicJsonType` value (and none of its per-element allocations) is ever built for the
    skipped ones.

    ```cpp
    --8<-- "examples/basic_json_view__materialize.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__materialize.output"
    ```

## See also

- [root](../basic_json_document/root.md) - the view of a document's root value
- [`BasicJsonType::parse`](../basic_json/parse.md) - build a `BasicJsonType` value directly from a JSON text
- [`JSON_DIAGNOSTIC_POSITIONS`](../macros/json_diagnostic_positions.md) - source positions on parsed values (not
  produced by `materialize()`)

## Version history

- Added in version 3.13.0.
