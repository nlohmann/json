# <small>nlohmann::ordered_map::</small>insert

```cpp
// (1)
std::pair<iterator, bool> insert(value_type&& value);
std::pair<iterator, bool> insert(const value_type& value);

// (2)
template<typename InputIt>
void insert(InputIt first, InputIt last);
```

1. Inserts `value` if no element with an equal key already exists (per [`key_compare`](key_compare.md)),
   appending it at the end to preserve insertion order. If an equal key already exists, does nothing.
2. Inserts the elements from range `[first, last)`, in iteration order, applying the same equal-key rule
   as (1) to each element.

## Template parameters

`InputIt`
:   an input iterator type

## Parameters

`value` (in)
:   value to insert

`first` (in)
:   iterator to the first element to insert

`last` (in)
:   iterator one past the last element to insert

## Return value

1. pair of an iterator to the (possibly newly inserted) element, and a `bool` that is `true` if insertion
   took place and `false` if an element with an equal key already existed
2. (none)

## Complexity

1. Linear in the number of elements.
2. Linear in the distance between `first` and `last`, times linear in the number of elements.

## Examples

??? example

    The example shows how `insert` is used.

    ```cpp
    --8<-- "examples/ordered_map__insert.cpp"
    ```

    Output:

    ```
    --8<-- "examples/ordered_map__insert.output"
    ```

## Version history

- Added in version 3.9.1 to implement [`nlohmann::ordered_json`](../ordered_json.md).
