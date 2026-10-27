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
    #include <iostream>
    #include <nlohmann/json_view.hpp>
    
    using nlohmann::json_document;
    
    int main()
    {
        // node_count() is the size of the flat index: one 16-byte node per value,
        // plus one per object key (values and keys are all the index stores)
        json_document scalar = json_document::parse("42");
        std::cout << scalar.node_count() << '\n';
    
        json_document doc = json_document::parse(R"({"a": 1, "b": [1, 2]})");
        std::cout << doc.node_count() << '\n';
    }
    
    ```

    Output:

    ```json
    1
    7
    
    ```

## See also

- [`memory_usage`](memory_usage.md) - the number of bytes held by the document
- [`shrink_to_fit`](shrink_to_fit.md) - release unused index capacity
- [Zero-copy JSON views](../../features/json_view.md#the-idea) - the flat node index and its memory

## Version history

- Added in version 3.13.0.
