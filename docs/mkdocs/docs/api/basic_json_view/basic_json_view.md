# <small>nlohmann::basic_json_view::</small>basic_json_view

```cpp
// (1)
basic_json_view() noexcept = default;

// (2) only for Mode == view_mode::editable
basic_json_view(const basic_json_view<BasicJsonType, view_mode::read_only>& other) noexcept;
```

1. Creates an invalid (discarded) view: [`type()`](type.md) is `#!cpp value_t::discarded` and
   [`is_discarded()`](is_discarded.md) is `#!cpp true`.
2. Converts a view of a read-only document into a view of an editable document (implicitly), so that a function
   taking a [`json_editable_view`](../json_editable_view.md) accepts both. The result is a view of the same value of
   the same read-only document. See [`view_mode`](../view_mode.md) for why there is no conversion the other way.

## Parameters

`other` (in)
:   a view of a read-only document with the same `BasicJsonType`

Apart from these, a view is obtained from a
[`basic_json_document`](../basic_json_document/index.md), via [`root()`](../basic_json_document/root.md) or by
navigating into a container with [`operator[]`](operator[].md), [`at`](at.md), [`front`](front.md), [`back`](back.md),
[`find`](find.md), or iteration.

## Exception safety

No-throw guarantee: these constructors never throw exceptions.

## Complexity

Constant.

## Notes

`basic_json_view` is trivially copyable (it holds two pointers), so a default-constructed view can be used as a
placeholder for "no value yet" and later be assigned a real view.

## Examples

??? example

    The example below shows the default constructor and that a `basic_json_view` is a small, copyable handle.

    ```cpp
    --8<-- "examples/basic_json_view__basic_json_view.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__basic_json_view.output"
    ```

## See also

- [is_discarded](is_discarded.md) - return whether the view is invalid
- [root](../basic_json_document/root.md) - the view of a document's root value
- [view_mode](../view_mode.md) - whether a document and its views can be edited

## Version history

- Added in version 3.13.0.
