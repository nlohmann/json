# nlohmann::basic_json_document::source

```
view_type::string_view_t source() const noexcept;
```

Returns the parsed text, whether it is borrowed from the caller or owned by the document.

## Return value

A `string_view_t` (`std::string_view` on C++17 and newer) over the parsed text, or an empty one if the document is [discarded](https://json.nlohmann.me/api/basic_json_document/is_discarded/index.md).

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

For a borrowed document, `source()` points directly into the caller's buffer, so it is only valid while that buffer is; see [`owns_source`](https://json.nlohmann.me/api/basic_json_document/owns_source/index.md).

## Examples

Example

```
#include <iostream>
#include <string>
#include <nlohmann/json_view.hpp>

using nlohmann::json_document;

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

```
true
{"a": 1}
true
```

## See also

- [`owns_source`](https://json.nlohmann.me/api/basic_json_document/owns_source/index.md) - return whether the document holds its own copy of the text
- [`source_offset`](https://json.nlohmann.me/api/basic_json_view/source_offset/index.md) - byte offset of a value in the source text
- [Zero-copy JSON views](https://json.nlohmann.me/features/json_view/#ownership-and-lifetime) - who owns the source text and for how long

## Version history

- Added in version 3.13.0 unreleased.
