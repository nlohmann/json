# <small>nlohmann::basic_json_view::</small>type

```cpp
value_t type() const noexcept;
```

Returns the type of the value this view refers to, as a value from the [`value_t`](../basic_json/value_t.md)
enumeration -- the same enumeration [`BasicJsonType::type()`](../basic_json/type.md) uses.

## Return value

The type of the value; `#!cpp value_t::discarded` for a [discarded](is_discarded.md) view.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

Unlike [`BasicJsonType::type()`](../basic_json/type.md), this function can never return `#!cpp value_t::binary`: a
JSON text has no binary values, so `type()` only distinguishes the eight ordinary JSON value types (plus
`#!cpp discarded`).

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

- [is_null](is_null.md), [is_boolean](is_boolean.md), [is_number](is_number.md), [is_string](is_string.md),
  [is_array](is_array.md), [is_object](is_object.md) - type-specific predicates built on `type()`
- [`BasicJsonType::type`](../basic_json/type.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
