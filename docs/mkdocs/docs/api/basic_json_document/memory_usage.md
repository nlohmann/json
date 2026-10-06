# <small>nlohmann::basic_json_document::</small>memory_usage

```cpp
std::size_t memory_usage() const noexcept;
```

Returns the number of bytes held by the document: the node index, the decoded-string buffer (for strings that
contain escapes), and, for an owned document, its copy of the source text.

## Return value

The number of bytes the document holds, `0` for a [discarded](is_discarded.md) document.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

The exact value depends on the platform, the allocator, and the library's own layout, and may change between
versions; do not rely on it being a specific number, and do not compare it across different builds or platforms.
Compare it for the same document over time, or between documents built with the same binary, instead -- for instance
to observe the effect of [`shrink_to_fit()`](shrink_to_fit.md).

## Examples

??? example

    ```cpp
    --8<-- "examples/basic_json_document__memory_usage.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_document__memory_usage.output"
    ```

## See also

- [node_count](node_count.md) - the number of index entries
- [shrink_to_fit](shrink_to_fit.md) - release unused index capacity

## Version history

- Added in version 3.13.0.
