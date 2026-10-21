# nlohmann::basic_json_view::items

```
/* unspecified */ items() const noexcept;
```

Returns a range of items -- (key, value) pairs -- for use in range-based for loops. An item's `key()` is a `string_view_t` (for an array element, its index converted to a string, as for [`BasicJsonType::items()`](https://json.nlohmann.me/api/basic_json/items/index.md)), and its `value()` is a `basic_json_view` of the element.

The returned type is not part of the public API and may change between versions; use a range-based for loop (see the example), or `decltype(v.items())` if you need to name it.

```
for (const auto& item : v.items())
{
    std::cout << "key: " << item.key() << ", value: " << item.value() << '\n';
}
```

On C++17, `item` also supports [structured bindings](https://en.cppreference.com/w/cpp/language/structured_binding):

```
for (const auto [key, value] : v.items())
{
    std::cout << "key: " << key << ", value: " << value << '\n';
}
```

Note the `const auto` (by value), not `const auto&`: unlike `BasicJsonType::items()`, whose elements are references into an existing object, a view's `item` is produced on the fly for each step of the iteration, so there is nothing for a reference to bind to.

## Return value

A range whose iterators dereference to an item (with `key()` and `value()`, see above) and whose `begin()`/`end()` are equivalent to [`basic_json_view::begin()`](https://json.nlohmann.me/api/basic_json_view/begin/index.md)/[`end()`](https://json.nlohmann.me/api/basic_json_view/end/index.md), in document order.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

As for [`begin()`](https://json.nlohmann.me/api/basic_json_view/begin/index.md)/[`end()`](https://json.nlohmann.me/api/basic_json_view/end/index.md), `items()` visits **every** member of an object, including all occurrences of a duplicate key -- unlike [`operator[]`](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/index.md), [`at`](https://json.nlohmann.me/api/basic_json_view/at/index.md), [`find`](https://json.nlohmann.me/api/basic_json_view/find/index.md), and [`contains`](https://json.nlohmann.me/api/basic_json_view/contains/index.md), which resolve to the *first* member with a given key. See the [Notes on duplicate keys](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/#notes) of `operator[]`.

Lifetime issues

Unlike `BasicJsonType::items()` (see [#2040](https://github.com/nlohmann/json/issues/2040)), calling `items()` on a temporary view is safe, for instance `for (auto item : v["a"].items())`: the returned range holds a copy of the view. What must outlive the loop is the document and, for a borrowed document, the source buffer.

## Examples

Example

The example below shows a settings object whose source text records every update to a key as a duplicate member, in the order they happened. `items()` walks all of them, so the update history is visible, while [`operator[]`](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/index.md) only ever sees the *first* one and [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) -- like [`BasicJsonType::parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md) -- keeps only the *last*.

```
#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    // a settings object whose source text records every update to a key as
    // a duplicate member. items() visits all of them, in document order, so
    // the update history is visible; operator[] only ever sees the first
    // one, and materialize() -- like basic_json::parse() -- keeps the last
    json_document updates = json_document::parse(R"({"retries": 1, "timeout": 30, "retries": 5})");
    const auto settings = updates.root();

    for (const auto& item : settings.items())
    {
        std::cout << item.key() << '=' << item.value().materialize().dump() << '\n';
    }

    std::cout << "first \"retries\" seen by operator[]: " << settings["retries"].materialize().dump() << '\n';
    std::cout << "last \"retries\" kept by materialize(): " << settings.materialize()["retries"].dump() << '\n';
}
```

Output:

```
retries=1
timeout=30
retries=5
first "retries" seen by operator[]: 1
last "retries" kept by materialize(): 5
```

## See also

- [begin](https://json.nlohmann.me/api/basic_json_view/begin/index.md), [end](https://json.nlohmann.me/api/basic_json_view/end/index.md) - the iterators `items()` is built on
- [`BasicJsonType::items`](https://json.nlohmann.me/api/basic_json/items/index.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0 unreleased.
