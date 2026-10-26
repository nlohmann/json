# nlohmann::basic_json_view::basic_json_view

```
// (1)
basic_json_view() noexcept = default;

// (2) only for Mode == view_mode::editable
basic_json_view(const basic_json_view<BasicJsonType, view_mode::read_only>& other) noexcept;
```

1. Creates an invalid (discarded) view: [`type()`](https://json.nlohmann.me/api/basic_json_view/type/index.md) is `value_t::discarded` and [`is_discarded()`](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md) is `true`.
1. Converts a view of a read-only document into a view of an editable document (implicitly), so that a function taking a [`json_editable_view`](https://json.nlohmann.me/api/json_editable_view/index.md) accepts both. The result is a view of the same value of the same read-only document. See [`view_mode`](https://json.nlohmann.me/api/view_mode/index.md) for why there is no conversion the other way.

## Parameters

`other` (in) : a view of a read-only document with the same `BasicJsonType`

Apart from these, a view is obtained from a [`basic_json_document`](https://json.nlohmann.me/api/basic_json_document/index.md), via [`root()`](https://json.nlohmann.me/api/basic_json_document/root/index.md) or by navigating into a container with [`operator[]`](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/index.md), [`at`](https://json.nlohmann.me/api/basic_json_view/at/index.md), [`front`](https://json.nlohmann.me/api/basic_json_view/front/index.md), [`back`](https://json.nlohmann.me/api/basic_json_view/back/index.md), [`find`](https://json.nlohmann.me/api/basic_json_view/find/index.md), or iteration.

## Exception safety

No-throw guarantee: these constructors never throw exceptions.

## Complexity

Constant.

## Notes

`basic_json_view` is trivially copyable (it holds two pointers), so a default-constructed view can be used as a placeholder for "no value yet" and later be assigned a real view.

## Examples

Example

The example below shows the default constructor and that a `basic_json_view` is a small, copyable handle.

```
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

```
true
true
```

## See also

- [is_discarded](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md) - return whether the view is invalid
- [root](https://json.nlohmann.me/api/basic_json_document/root/index.md) - the view of a document's root value
- [view_mode](https://json.nlohmann.me/api/view_mode/index.md) - whether a document and its views can be edited

## Version history

- Added in version 3.13.0 unreleased.
