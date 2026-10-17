# <small>nlohmann::basic_json_document::</small>node_count

```cpp
std::size_t node_count() const noexcept;
```

Returns the number of entries in the document's flat index.

## Return value

The number of index entries: one per value (of any type, at any nesting depth) plus one per object key. `0` for a
[discarded](is_discarded.md) document.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

Each index entry is [16 bytes](../../home/architecture.md#node-index-of-json-views), so `#!cpp node_count() * 16` is
the size of the index itself (part, but not all, of [`memory_usage()`](memory_usage.md), which also counts decoded
strings and, for an owned document, the text).

## Examples

??? example

    ```cpp
    --8<-- "examples/basic_json_document__node_count.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_document__node_count.output"
    ```

## See also

- [memory_usage](memory_usage.md) - the number of bytes held by the document
- [shrink_to_fit](shrink_to_fit.md) - release unused index capacity

## Version history

- Added in version 3.13.0.
