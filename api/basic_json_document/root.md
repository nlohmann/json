# <small>nlohmann::basic_json_document::</small>root

```cpp
// (1)
view_type root() const& noexcept;

// (2)
view_type root() const&& = delete;
```

1. Returns a view of the root value of the document.
2. Deleted: the view of a temporary document would dangle.

## Return value

A [`view_type`](index.md#member-types) (i.e. `#!cpp basic_json_view<BasicJsonType>`) for the root value, or a
discarded view if the document is [discarded](is_discarded.md).

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

**Lifetime.** A view refers into the document, so the document must outlive it. `root()` can therefore only be called
on a document that has a name (an lvalue); calling it on a temporary does not compile:

```cpp
auto v = json_document::parse(text).root();  // error: the document is destroyed at the end of the statement

auto doc = json_document::parse(text);       // OK: keep the document alive
auto v = doc.root();
```

`root()` is a cheap handle into the document's index, not a copy of anything; call it as often as needed. The
returned view is valid under the same conditions as any other view of the document -- see
[Object inspection](../basic_json_view/index.md) -- in particular, it is invalidated by the next
[`read()`](read.md) or [`shrink_to_fit()`](shrink_to_fit.md) on this document. A view can dangle, like a
`#!cpp std::string_view`; see [Ownership and lifetime](../../features/json_view.md#ownership-and-lifetime).

## Examples

??? example

    ```cpp
    #include <iostream>
    #include <nlohmann/json_view.hpp>
    
    using nlohmann::json_document;
    
    int main()
    {
        std::cout << std::boolalpha;
    
        json_document doc = json_document::parse(R"({"greeting": "hi"})");
        std::cout << doc.root().is_object() << '\n';
    
        // root() is a cheap handle, not a copy: repeated calls observe the same value
        std::cout << (doc.root().type() == doc.root().type()) << '\n';
    
        // the root of a failed parse (allow_exceptions == false) is discarded
        json_document failed = json_document::parse("{", false);
        std::cout << failed.root().is_discarded() << '\n';
    }
    
    ```

    Output:

    ```json
    true
    true
    true
    
    ```

## See also

- [is_discarded](is_discarded.md) - return whether the last parse failed
- [materialize](../basic_json_view/materialize.md) - build the `BasicJsonType` value of a subtree

## Version history

- Added in version 3.13.0.
