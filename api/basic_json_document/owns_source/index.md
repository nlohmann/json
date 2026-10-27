# nlohmann::basic_json_document::owns_source

```
bool owns_source() const noexcept;
```

Returns whether the document holds its own copy of the parsed text or is borrowing the caller's buffer.

## Return value

`true` if the document owns the text returned by [`source()`](https://json.nlohmann.me/api/basic_json_document/source/index.md), `false` if it borrows it (or if the document is [discarded](https://json.nlohmann.me/api/basic_json_document/is_discarded/index.md)).

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

See the ownership table on [`parse`](https://json.nlohmann.me/api/basic_json_document/parse/#notes) for which inputs are borrowed and which are owned. A borrowed document (`owns_source() == false`) is only valid while the buffer it was parsed from is still alive.

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

```
false
true
true
```

## See also

- [`parse`](https://json.nlohmann.me/api/basic_json_document/parse/index.md) - deserialize from a compatible input
- [`parse_copy`](https://json.nlohmann.me/api/basic_json_document/parse_copy/index.md) - deserialize a copy of a compatible input, always owned
- [`source`](https://json.nlohmann.me/api/basic_json_document/source/index.md) - the parsed text
- [Zero-copy JSON views](https://json.nlohmann.me/features/json_view/#ownership-and-lifetime) - who owns the source text and for how long

## Version history

- Added in version 3.13.0 unreleased.
