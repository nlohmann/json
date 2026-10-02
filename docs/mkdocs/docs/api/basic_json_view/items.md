# <small>nlohmann::basic_json_view::</small>items

```cpp
/* unspecified */ items() const noexcept;
```

Returns a range of [`item`](index.md#member-types) values -- (key, value) pairs -- for use in range-based for loops.
The key of an array element is its index, converted to a string, as for
[`BasicJsonType::items()`](../basic_json/items.md).

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

A range whose iterators dereference to [`item`](index.md#member-types) and whose `#!cpp begin()`/`#!cpp end()` are
equivalent to [`basic_json_view::begin()`](begin.md)/[`end()`](end.md), in document order.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

As for [`begin()`](begin.md)/[`end()`](end.md), `items()` visits **every** member of an object, including all
occurrences of a duplicate key -- unlike [`operator[]`](operator[].md), [`at`](at.md), [`find`](find.md),
[`contains`](contains.md), and [`count`](count.md), which resolve to the *first* member with a given key. See the
[Notes on duplicate keys](operator[].md#notes) of `operator[]`.

!!! danger "Lifetime issues"

    As for `BasicJsonType::items()`, calling `items()` on a temporary view (or a temporary document) is dangerous:
    the range refers back to the document, so the document must outlive the loop. See
    [#2040](https://github.com/nlohmann/json/issues/2040) for the `BasicJsonType` background.

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
