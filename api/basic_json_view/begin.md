# <small>nlohmann::basic_json_view::</small>begin

```cpp
iterator begin() const noexcept;
```

Returns an iterator to the first element of an array, or the first member value of an object, in **document order**
— the order the values appear in the source text, not sorted by key. A primitive value iterates as a range of one
element (itself), and a `#!json null` value or a [discarded](is_discarded.md) view iterates as an empty range.

## Return value

Iterator to the first element.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

For an object, iteration visits **every** member, including all occurrences of a duplicate key — unlike
[`operator[]`](operator[].md), [`at`](at.md), [`find`](find.md), and [`contains`](contains.md),
which all resolve to the *first* member with a given key. See the
[Notes on duplicate keys](operator[].md#notes) of `operator[]`.

Because objects are iterated in document order rather than sorted by key, the order seen here can differ from what
iterating the [`materialize()`](materialize.md)d `BasicJsonType` value would produce: a `#!cpp basic_json` object
(`std::map`-backed by default) sorts its keys, while a view does not.

An `ordered_json` value also keeps document order, but it keeps only one entry per key: as `parse()` does, it keeps the
*last* value, at the position of the key's *first* occurrence. The view, in contrast, visits every member, including
the duplicates.

## Examples

??? example

    The example below iterates a log record's members with `begin()`/[`end()`](end.md) and prints them in the order
    they were written. Materializing the record into a `BasicJsonType` object and iterating that would instead print
    the members sorted by key.

    ```cpp
    #include <iostream>
    #include <nlohmann/json_view.hpp>
    
    using nlohmann::json_document;
    
    int main()
    {
        // a log record: the fields matter in the order they were written, e.g.
        // to reproduce the record as it was logged. A nlohmann::json object
        // sorts its keys, so materializing and iterating it would instead print
        // them alphabetically ("level", "message", "time")
        json_document record = json_document::parse(R"({"time": "10:00:01", "level": "info", "message": "started"})");
    
        for (auto it = record.root().begin(); it != record.root().end(); ++it)
        {
            std::cout << it.key() << '=' << it->materialize().dump() << '\n';
        }
    }
    
    ```

    Output:

    ```json
    time="10:00:01"
    level="info"
    message="started"
    
    ```

## See also

- [`end`](end.md) - returns an iterator to one past the last element
- [`cbegin`](cbegin.md) - returns a const iterator to the first element
- [`items`](items.md) - access iterator member functions in range-based for
- [`BasicJsonType::begin`](../basic_json/begin.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
