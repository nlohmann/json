# nlohmann::basic_json_document::is_discarded

```
bool is_discarded() const noexcept;
```

Returns whether the document holds no value, either because it was default-constructed or because the last call to [`parse()`](https://json.nlohmann.me/api/basic_json_document/parse/index.md), [`parse_copy()`](https://json.nlohmann.me/api/basic_json_document/parse_copy/index.md), or [`read()`](https://json.nlohmann.me/api/basic_json_document/read/index.md) failed with `allow_exceptions` set to `false`.

## Return value

`true` if the document is discarded, `false` otherwise.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

When the document is discarded, [`root()`](https://json.nlohmann.me/api/basic_json_document/root/index.md) returns a discarded view (its [`is_discarded()`](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md) is also `true`).

## Examples

Example

```
#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    std::cout << std::boolalpha;

    // with allow_exceptions == false, a parse error produces a discarded
    // document instead of throwing -- exactly like basic_json::parse()
    json_document doc = json_document::parse(R"({"a": )", /* allow_exceptions */ false);
    std::cout << doc.is_discarded() << '\n';
    std::cout << doc.root().is_discarded() << '\n';

    // a successful parse is never discarded
    json_document ok = json_document::parse(R"({"a": 1})", false);
    std::cout << ok.is_discarded() << '\n';
}
```

Output:

```
true
true
false
```

## See also

- [parse](https://json.nlohmann.me/api/basic_json_document/parse/index.md) - deserialize from a compatible input
- [is_discarded (basic_json_view)](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md) - return whether a view is invalid

## Version history

- Added in version 3.13.0 unreleased.
