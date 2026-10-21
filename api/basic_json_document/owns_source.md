# <small>nlohmann::basic_json_document::</small>owns_source

```cpp
bool owns_source() const noexcept;
```

Returns whether the document holds its own copy of the parsed text or is borrowing the caller's buffer.

## Return value

`#!cpp true` if the document owns the text returned by [`source()`](source.md), `#!cpp false` if it borrows it (or if
the document is [discarded](is_discarded.md)).

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

See the ownership table on [`parse`](parse.md#notes) for which inputs are borrowed and which are owned. A borrowed
document (`#!cpp owns_source() == false`) is only valid while the buffer it was parsed from is still alive.

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
    
        // borrowed: the document only points into `text`; `text` must outlive it
        json_document borrowed = json_document::parse(text);
        std::cout << borrowed.owns_source() << '\n';
    
        // owned: parse_copy() always takes its own copy
        json_document copied = json_document::parse_copy(text);
        std::cout << copied.owns_source() << '\n';
    
        // owned: an rvalue std::string is moved in, not copied, but still owned
        json_document moved_in = json_document::parse(std::string(text));
        std::cout << moved_in.owns_source() << '\n';
    }
    
    ```

    Output:

    ```json
    false
    true
    true
    
    ```

## See also

- [parse](parse.md) - deserialize from a compatible input
- [parse_copy](parse_copy.md) - deserialize a copy of a compatible input, always owned
- [source](source.md) - the parsed text

## Version history

- Added in version 3.13.0.
