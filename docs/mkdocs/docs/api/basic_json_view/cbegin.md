# <small>nlohmann::basic_json_view::</small>cbegin

```cpp
iterator cbegin() const noexcept;
```

Returns an iterator to the first element, in [document order](begin.md). Equivalent to [`begin()`](begin.md): a view
is always read-only, so `#!cpp const_iterator` and `#!cpp iterator` are the same type, and `cbegin()` exists only so
that generic code that expects a `cbegin()`/`cend()` pair works with a view too.

## Return value

Iterator to the first element; identical to what [`begin()`](begin.md) returns.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Examples

??? example

    The example below sums many measurements with `std::accumulate`, using `cbegin()`/[`cend()`](cend.md) as the
    range -- the same way it would for any standard container -- without ever materializing the whole array into a
    `BasicJsonType` value.

    ```cpp
    --8<-- "examples/basic_json_view__cbegin.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__cbegin.output"
    ```

## See also

- [begin](begin.md) - returns an iterator to the first element
- [cend](cend.md) - returns a const iterator to one past the last element
- [`BasicJsonType::cbegin`](../basic_json/cbegin.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
