# <small>nlohmann::basic_json_view::</small>items

```cpp
/* unspecified */ items() const noexcept;
```

Returns a range of items -- (key, value) pairs -- for use in range-based for loops. An item's `#!cpp key()` is a
`#!cpp string_view_t` (for an array element, its index converted to a string, as for
[`BasicJsonType::items()`](../basic_json/items.md)), and its `#!cpp value()` is a `basic_json_view` of the element.

The returned type is not part of the public API and may change between versions; use a range-based for loop (see the
example), or `#!cpp decltype(v.items())` if you need to name it.

```cpp
for (const auto& item : v.items())
{
    std::cout << "key: " << item.key() << ", value: " << item.value() << '\n';
}
```

On C++17, `item` also supports [structured bindings](https://en.cppreference.com/w/cpp/language/structured_binding):

```cpp
for (const auto [key, value] : v.items())
{
    std::cout << "key: " << key << ", value: " << value << '\n';
}
```

Note the `#!cpp const auto` (by value), not `#!cpp const auto&`: unlike `BasicJsonType::items()`, whose elements are
references into an existing object, a view's `item` is produced on the fly for each step of the iteration, so there
is nothing for a reference to bind to.

## Return value

A range whose iterators dereference to an item (with `#!cpp key()` and `#!cpp value()`, see above) and whose
`#!cpp begin()`/`#!cpp end()` are equivalent to [`basic_json_view::begin()`](begin.md)/[`end()`](end.md), in document order.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

As for [`begin()`](begin.md)/[`end()`](end.md), `items()` visits **every** member of an object, including all
occurrences of a duplicate key -- unlike [`operator[]`](operator[].md), [`at`](at.md), [`find`](find.md),
and [`contains`](contains.md), which resolve to the *first* member with a given key. See the
[Notes on duplicate keys](operator[].md#notes) of `operator[]`.

!!! danger "Lifetime issues"

    Unlike `BasicJsonType::items()` (see [#2040](https://github.com/nlohmann/json/issues/2040)), calling `items()` on
    a temporary view is safe, for instance `#!cpp for (auto item : v["a"].items())`: the returned range holds a copy
    of the view. What must outlive the loop is the document and, for a borrowed document, the source buffer.

## Examples

??? example

    The example below shows a settings object whose source text records every update to a key as a duplicate
    member, in the order they happened. `items()` walks all of them, so the update history is visible, while
    [`operator[]`](operator[].md) only ever sees the *first* one and [`materialize()`](materialize.md) -- like
    [`BasicJsonType::parse()`](../basic_json/parse.md) -- keeps only the *last*.

    ```cpp
    --8<-- "examples/basic_json_view__items.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__items.output"
    ```

## See also

- [begin](begin.md), [end](end.md) - the iterators `items()` is built on
- [`BasicJsonType::items`](../basic_json/items.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
