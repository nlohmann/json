# <small>nlohmann::basic_json_view::</small>basic_json_view

```cpp
basic_json_view() noexcept = default;
```

Creates an invalid (discarded) view: [`type()`](type.md) is `#!cpp value_t::discarded` and
[`is_discarded()`](is_discarded.md) is `#!cpp true`.

This is the only constructor a caller can use directly. Every other view is obtained from a
[`basic_json_document`](../basic_json_document/index.md), via [`root()`](../basic_json_document/root.md) or by
navigating into a container with [`operator[]`](operator[].md), [`at`](at.md), [`front`](front.md), [`back`](back.md),
[`find`](find.md), or iteration.

## Exception safety

No-throw guarantee: this constructor never throws exceptions.

## Complexity

Constant.

## Notes

`basic_json_view` is trivially copyable (it holds two pointers), so a default-constructed view can be used as a
placeholder for "no value yet" and later be assigned a real view.

## Examples

??? example

    The example below shows the default constructor and that a `basic_json_view` is a small, copyable handle.

    ```cpp
    #include <iostream>
    #include <nlohmann/json_view.hpp>
    
    int main()
    {
        std::cout << std::boolalpha;
    
        // the default constructor is the only public one: it creates an invalid
        // (discarded) view, useful as a "no value yet" placeholder
        nlohmann::json_view v;
        std::cout << v.is_discarded() << '\n';
    
        // views are trivially copyable handles (two pointers); the document owns
        // the actual data
        nlohmann::json_view copy = v;
        std::cout << copy.is_discarded() << '\n';
    }
    
    ```

    Output:

    ```json
    true
    true
    
    ```

## See also

- [is_discarded](is_discarded.md) - return whether the view is invalid
- [root](../basic_json_document/root.md) - the view of a document's root value

## Version history

- Added in version 3.13.0.
