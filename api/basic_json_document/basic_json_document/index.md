# nlohmann::basic_json_document::basic_json_document

```
// (1)
basic_json_document() = default;

// (2)
basic_json_document(basic_json_document&& other) noexcept = default;

// (3)
basic_json_document(const basic_json_document&) = delete;
```

1. Creates an empty (discarded) document: [`root()`](https://json.nlohmann.me/api/basic_json_document/root/index.md) returns a discarded view, and [`is_discarded()`](https://json.nlohmann.me/api/basic_json_document/is_discarded/index.md) is `true`.
1. Move constructor. Takes over `other`'s index and, if owned, its text; `other` is left as an empty document. Views taken from `other` before the move remain valid, because the index is heap-allocated independently of the `basic_json_document` object.
1. `basic_json_document` is move-only. Copying is disabled because of its cost: a copy would duplicate the whole index, the decoded-string buffer, and the owned text, while a move is enough in every use we know of.

## Parameters

`other` (in) : another document to move the index and text from

## Exception safety

No-throw guarantee: the default and move constructors never throw exceptions.

## Complexity

Constant.

## Examples

Example

The example below shows the default constructor and demonstrates that `basic_json_document` is move-only.

```
#include <iostream>
#include <utility>
#include <nlohmann/json_view.hpp>

using nlohmann::json_document;

int main()
{
    std::cout << std::boolalpha;

    // the default constructor creates an empty (discarded) document
    json_document empty;
    std::cout << empty.is_discarded() << '\n';

    // json_document is move-only: parse() itself returns by value (moved out),
    // and a document can be moved again, e.g. into a container
    json_document doc = json_document::parse(R"({"a": 1})");
    json_document moved = std::move(doc);
    std::cout << moved.root().is_object() << '\n';

    // copying is disabled at compile time:
    // json_document another = moved; // does not compile
}
```

Output:

```
true
true
```

## See also

- [parse](https://json.nlohmann.me/api/basic_json_document/parse/index.md) - deserialize from a compatible input
- [is_discarded](https://json.nlohmann.me/api/basic_json_document/is_discarded/index.md) - return whether the last parse failed

## Version history

- Added in version 3.13.0 unreleased.
