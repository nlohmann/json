# <small>nlohmann::basic_json_view::</small>end

```cpp
iterator end() const noexcept;
```

Returns an iterator to one past the last element of an array, one past the last member value of an object, in
**document order** -- see [`begin()`](begin.md). A primitive value iterates as a range of one element (itself);
`#!json null` and a [discarded](is_discarded.md) view iterate as an empty range, so `#!cpp begin() == end()` for
them.

## Return value

Iterator one past the last element.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

`#!cpp iterator` is a forward iterator: unlike `BasicJsonType::iterator`, it cannot be decremented, so there is no
way to reach the last element by stepping back from `end()`. Use [`back()`](back.md) instead.

## Examples

??? example

    The example below scans a (possibly large) array of readings for the first one over a threshold, stopping the
    loop at `end()` as soon as one is found. Only the matching reading, if any, is ever materialized.

    ```cpp
    --8<-- "examples/basic_json_view__end.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__end.output"
    ```

## See also

- [begin](begin.md) - returns an iterator to the first element
- [cend](cend.md) - returns a const iterator to one past the last element
- [`BasicJsonType::end`](../basic_json/end.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
