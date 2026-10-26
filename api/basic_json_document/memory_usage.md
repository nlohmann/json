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
    #include <iostream>
    #include <string>
    #include <nlohmann/json_view.hpp>
    
    using nlohmann::json_document;
    
    int main()
    {
        std::cout << std::boolalpha;
    
        // long enough that copying it needs a real (heap) allocation, so the
        // comparison below does not depend on the standard library's small
        // string optimization threshold
        const std::string text = std::string(200, ' ') + "[1, 2, 3, 4, 5]";
    
        // memory_usage() is not portable across platforms/allocators/compilers, so
        // compare it relatively instead of printing the raw byte count
        json_document borrowed = json_document::parse(text);
        json_document owned = json_document::parse_copy(text);
    
        // the owned document additionally stores its own copy of the source text
        std::cout << (owned.memory_usage() > borrowed.memory_usage()) << '\n';
    
        // a document with more values needs a larger index
        json_document small = json_document::parse(std::string("[1]"));
        json_document large = json_document::parse(std::string("[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]"));
        std::cout << (large.memory_usage() > small.memory_usage()) << '\n';
    }
    
    ```

    Output:

    ```json
    true
    true
    
    ```

## See also

- [node_count](node_count.md) - the number of index entries
- [shrink_to_fit](shrink_to_fit.md) - release unused index capacity

## Version history

- Added in version 3.13.0.
