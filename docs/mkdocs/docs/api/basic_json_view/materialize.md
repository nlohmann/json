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

With [`JSON_DIAGNOSTIC_POSITIONS`](../macros/json_diagnostic_positions.md) enabled, the values get the source
positions [`BasicJsonType::parse()`](../basic_json/parse.md) would give them, also for the subtree of a view (the
positions are those in the document's whole source text), and exceptions about them name the same bytes. For values of
an [editable document](../json_editable_document.md), positions are all-or-nothing, and [`start_pos()`](../basic_json/start_pos.md)
and [`end_pos()`](../basic_json/end_pos.md) return `std::string::npos` for

- a value written by an edit (a copy of an array or object of the document is also new; copies of its scalars keep
  their positions),
- an array or object whose elements were changed (its elements keep theirs), and
- an array or object whose last element has no positions (its end is found from that element).

A `basic_json` value, in contrast, keeps its positions when it is changed. Documents [loaded](../basic_json_document/load.md)
from an image have the positions of the saved document, except that its strings with escapes have none if it was saved
without `JSON_DIAGNOSTIC_POSITIONS`.

Calling `materialize()` on the same view repeatedly builds a new, independent `BasicJsonType` value each time; it
never caches the result.

## Examples

??? example

    The example below skips messages that are not useful — a discarded value, or an empty array — using only
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

- [`root`](../basic_json_document/root.md) - the view of a document's root value
- [`BasicJsonType::parse`](../basic_json/parse.md) - build a `BasicJsonType` value directly from a JSON text
- [`JSON_DIAGNOSTIC_POSITIONS`](../macros/json_diagnostic_positions.md) - source positions on parsed values
- [Zero-copy JSON views](../../features/json_view.md#getting-values-out-without-copying) - when to build a basic_json value from a view

## Version history

- Added in version 3.13.0.
