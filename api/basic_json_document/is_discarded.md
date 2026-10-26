# <small>nlohmann::basic_json_document::</small>is_discarded

```cpp
bool is_discarded() const noexcept;
```

Returns whether the document holds no value, either because it was default-constructed or because the last call to
[`parse()`](parse.md), [`parse_copy()`](parse_copy.md), or [`read()`](read.md) failed with `allow_exceptions` set to
`#!cpp false`.

## Return value

`#!cpp true` if the document is discarded, `#!cpp false` otherwise.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

When the document is discarded, [`root()`](root.md) returns a discarded view (its
[`is_discarded()`](../basic_json_view/is_discarded.md) is also `#!cpp true`).

## Examples

??? example

    ```cpp
    #include <iostream>
    #include <nlohmann/json_view.hpp>
    
    using nlohmann::json_document;
    
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

    ```json
    true
    true
    false
    
    ```

## See also

- [parse](parse.md) - deserialize from a compatible input
- [is_discarded (basic_json_view)](../basic_json_view/is_discarded.md) - return whether a view is invalid

## Version history

- Added in version 3.13.0.
