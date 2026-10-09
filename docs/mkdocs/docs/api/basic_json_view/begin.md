# <small>nlohmann::basic_json_view::</small>begin

```cpp
iterator begin() const noexcept;
```

Returns an iterator to the first element of an array, or the first member value of an object, in **document order**
-- the order the values appear in the source text, not sorted by key. A primitive value iterates as a range of one
element (itself); `#!json null` and a [discarded](is_discarded.md) view iterate as an empty range.

## Return value

Iterator to the first element.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

For an object, iteration visits **every** member, including all occurrences of a duplicate key -- unlike
[`operator[]`](operator[].md), [`at`](at.md), [`find`](find.md), [`contains`](contains.md), and [`count`](count.md),
which all resolve to the *first* member with a given key. See the
[Notes on duplicate keys](operator[].md#notes) of `operator[]`.

Because objects are iterated in document order rather than sorted by key, the order seen here can differ from what
iterating the [`materialize()`](materialize.md)d `BasicJsonType` value would produce: a `#!cpp basic_json` object
(`std::map`-backed by default) sorts its keys, while a view does not.

## Examples

??? example

    The example below iterates a log record's members with `begin()`/[`end()`](end.md) and prints them in the order
    they were written. Materializing the record into a `BasicJsonType` object and iterating that would instead print
    the members sorted by key.

    ```cpp
    --8<-- "examples/basic_json_view__begin.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__begin.output"
    ```

## See also

- [end](end.md) - returns an iterator to one past the last element
- [cbegin](cbegin.md) - returns a const iterator to the first element
- [items](items.md) - access iterator member functions in range-based for
- [`BasicJsonType::begin`](../basic_json/begin.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
