# <small>nlohmann::basic_json_view::</small>basic_json_view

```cpp
basic_json_view() noexcept = default;
```

Creates an invalid (discarded) view: [`type()`](type.md) is `#!cpp value_t::discarded`,
[`is_discarded()`](is_discarded.md) is `#!cpp true`, and `#!cpp explicit operator bool()` is `#!cpp false`.

This is the only constructor a caller can use directly. Every other view is obtained from a
[`basic_json_document`](../basic_json_document/index.md), via [`root()`](../basic_json_document/root.md) or by
navigating into a container with [`operator[]`](operator[].md), [`at`](at.md), [`front`](front.md), [`back`](back.md),
[`find`](find.md), or iteration.

## Exception safety

No-throw guarantee: this constructor never throws exceptions.

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
- [operator bool](operator_bool.md) - return whether the view refers to a value
- [root](../basic_json_document/root.md) - the view of a document's root value

## Version history

- Added in version 3.13.0.
