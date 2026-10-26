# <small>nlohmann::basic_json::</small>begin

```cpp
iterator begin() noexcept;
const_iterator begin() const noexcept;
```

Returns an iterator to the first element.

<div class="nj-fig-wrap" markdown>
--8<-- "images/range-begin-end.svg"
</div>

<p class="nj-caption" markdown>`begin()` points to the first element and `end()` to the position after the last element;
the dashed cell is the past-the-last position, which must not be dereferenced.</p>

## Return value

iterator to the first element

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Examples

??? example

    The following code shows an example for `begin()`.
    
    ```cpp
    --8<-- "examples/begin.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/begin.output"
    ```

## See also

- [`end`](end.md) - returns an iterator to one past the last element
- [`cbegin`](cbegin.md) - returns a const iterator to the first element
- [`rbegin`](rbegin.md) - returns a reverse iterator to the last element
- [`items`](items.md) - returns an iteration proxy to access keys and values during range-based for loops
- [Iterators](../../features/iterators.md) - the article on iterators
- [`basic_json_view::begin`](../basic_json_view/begin.md) - the same iteration on a zero-copy view (in document order,
  not sorted by key)

## Version history

- Added in version 1.0.0.
