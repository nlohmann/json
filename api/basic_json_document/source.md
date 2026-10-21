# <small>nlohmann::basic_json_document::</small>source

```cpp
view_type::string_view_t source() const noexcept;
```

Returns the parsed text, whether it is borrowed from the caller or owned by the document.

## Return value

A `#!cpp string_view_t` (`#!cpp std::string_view` on C++17 and newer) over the parsed text, or an empty one if the
document is [discarded](is_discarded.md).

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

For a borrowed document, `source()` points directly into the caller's buffer, so it is only valid while that buffer
is; see [`owns_source`](owns_source.md).

## Examples

??? example

    ```cpp
    #include <iostream>
    #include <string>
    #include <nlohmann/json_view.hpp>
    
    using json_document = nlohmann::json_document;
    
    int main()
    {
        std::cout << std::boolalpha;
    
        std::string text = R"({"a": 1})";
        json_document doc = json_document::parse(text);
    
        // source() is the parsed text, whether borrowed or owned
        std::cout << (doc.source().size() == text.size()) << '\n';
        std::cout << std::string(doc.source().data(), doc.source().size()) << '\n';
    
        // for a borrowed document, source() points right into the caller's buffer
        std::cout << (doc.source().data() == text.data()) << '\n';
    }
    
    ```

    Output:

    ```json
    true
    {"a": 1}
    true
    
    ```

## See also

- [owns_source](owns_source.md) - return whether the document holds its own copy of the text
- [source_offset](../basic_json_view/source_offset.md) - byte offset of a value in the source text

## Version history

- Added in version 3.13.0.
