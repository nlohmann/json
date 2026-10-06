# <small>nlohmann::basic_json_view::</small>operator bool

```cpp
explicit operator bool() const noexcept;
```

Returns whether this view refers to a value, i.e. the negation of [`is_discarded()`](is_discarded.md). Being
`#!cpp explicit`, this conversion is only considered in a boolean context (`#!cpp if (v)`, `#!cpp !v`, `#!cpp v &&
...`), not for implicit conversions to other types.

## Return value

`#!cpp true` if the view refers to a value, `#!cpp false` if it is [discarded](is_discarded.md).

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Examples

??? example

    The example below classifies several parsed documents by the type of their root value, without materializing any
    of them into a `BasicJsonType` value.

    ```cpp
    --8<-- "examples/basic_json_view__type_predicates.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__type_predicates.output"
    ```

## See also

- [is_discarded](is_discarded.md) - return whether the view is invalid

## Version history

- Added in version 3.13.0.
