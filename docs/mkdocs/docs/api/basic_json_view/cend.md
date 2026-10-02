# <small>nlohmann::basic_json_view::</small>cend

```cpp
iterator cend() const noexcept;
```

Returns an iterator to one past the last element, in [document order](begin.md). Equivalent to [`end()`](end.md): a
view is always read-only, so `#!cpp const_iterator` and `#!cpp iterator` are the same type, and `cend()` exists only
so that generic code that expects a `cbegin()`/`cend()` pair works with a view too.

## Return value

Iterator one past the last element; identical to what [`end()`](end.md) returns.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Examples

??? example

    The example below checks that every record of a batch is an object with `std::all_of`, using
    [`cbegin()`](cbegin.md)/`cend()` as the range -- the same way it would for any standard container -- before
    materializing any record of the batch.

    ```cpp
    --8<-- "examples/basic_json_view__cend.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__cend.output"
    ```

## See also

- [end](end.md) - returns an iterator to one past the last element
- [cbegin](cbegin.md) - returns a const iterator to the first element
- [`BasicJsonType::cend`](../basic_json/cend.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
