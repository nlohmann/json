# nlohmann::basic_json_document::node_count

```
std::size_t node_count() const noexcept;
```

Returns the number of entries in the document's flat index.

## Return value

The number of index entries: one per value (of any type, at any nesting depth) plus one per object key. `0` for a [discarded](https://json.nlohmann.me/api/basic_json_document/is_discarded/index.md) document.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

Each index entry is [16 bytes](https://json.nlohmann.me/home/architecture/#node-index-of-json-views), so `node_count() * 16` is the size of the index itself (part, but not all, of [`memory_usage()`](https://json.nlohmann.me/api/basic_json_document/memory_usage/index.md), which also counts decoded strings and, for an owned document, the text).

## Examples

Example

```
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

```
1
7
```

## See also

- [memory_usage](https://json.nlohmann.me/api/basic_json_document/memory_usage/index.md) - the number of bytes held by the document
- [shrink_to_fit](https://json.nlohmann.me/api/basic_json_document/shrink_to_fit/index.md) - release unused index capacity

## Version history

- Added in version 3.13.0 unreleased.
