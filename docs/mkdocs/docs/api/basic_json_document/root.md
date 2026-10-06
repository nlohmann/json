# <small>nlohmann::basic_json_document::</small>root

```cpp
view_type root() const noexcept;
```

Returns a view of the root value of the document.

## Return value

A [`view_type`](index.md#member-types) (i.e. `#!cpp basic_json_view<BasicJsonType>`) for the root value, or a
discarded view if the document is [discarded](is_discarded.md).

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

`root()` is a cheap handle into the document's index, not a copy of anything; call it as often as needed. The
returned view is valid under the same conditions as any other view of the document -- see
[Object inspection](../basic_json_view/index.md) -- in particular, it is invalidated by the next
[`read()`](read.md) or [`shrink_to_fit()`](shrink_to_fit.md) on this document.

## Examples

??? example

    ```cpp
    --8<-- "examples/basic_json_document__root.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_document__root.output"
    ```

## See also

- [is_discarded](is_discarded.md) - return whether the last parse failed
- [materialize](../basic_json_view/materialize.md) - build the `BasicJsonType` value of a subtree

## Version history

- Added in version 3.13.0.
