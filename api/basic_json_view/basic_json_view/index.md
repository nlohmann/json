# nlohmann::basic_json_view::basic_json_view

```
basic_json_view() noexcept = default;
```

Creates an invalid (discarded) view: [`type()`](https://json.nlohmann.me/api/basic_json_view/type/index.md) is `value_t::discarded` and [`is_discarded()`](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md) is `true`.

This is the only constructor a caller can use directly. Every other view is obtained from a [`basic_json_document`](https://json.nlohmann.me/api/basic_json_document/index.md), via [`root()`](https://json.nlohmann.me/api/basic_json_document/root/index.md) or by navigating into a container with [`operator[]`](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/index.md), [`at`](https://json.nlohmann.me/api/basic_json_view/at/index.md), [`front`](https://json.nlohmann.me/api/basic_json_view/front/index.md), [`back`](https://json.nlohmann.me/api/basic_json_view/back/index.md), [`find`](https://json.nlohmann.me/api/basic_json_view/find/index.md), or iteration.

## Exception safety

No-throw guarantee: this constructor never throws exceptions.

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

## Version history

- Added in version 3.13.0 unreleased.
