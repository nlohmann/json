# <small>nlohmann::basic_json_document::</small>is_discarded

```cpp
bool is_discarded() const noexcept;
```

Returns whether the document holds no value, either because it was default-constructed or because the last call to
[`parse()`](parse.md), [`parse_copy()`](parse_copy.md), or [`read()`](read.md) failed with `allow_exceptions` set to
`#!cpp false`.

## Return value

`#!cpp true` if the document is discarded, `#!cpp false` otherwise.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

When the document is discarded, [`root()`](root.md) returns a discarded view (its
[`is_discarded()`](../basic_json_view/is_discarded.md) is also `#!cpp true`).

## Examples

??? example

    ```cpp
    --8<-- "examples/basic_json_document__is_discarded.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_document__is_discarded.output"
    ```

## See also

- [parse](parse.md) - deserialize from a compatible input
- [is_discarded (basic_json_view)](../basic_json_view/is_discarded.md) - return whether a view is invalid

## Version history

- Added in version 3.13.0.
