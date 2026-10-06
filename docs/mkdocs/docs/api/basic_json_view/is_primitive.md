# <small>nlohmann::basic_json_view::</small>is_primitive

```cpp
bool is_primitive() const noexcept;
```

This function returns `#!cpp true` if and only if the value is primitive, i.e. `#!json null`, a boolean, a number, or a string. It is defined as `#!cpp is_null() || is_string() || is_boolean() || is_number()`.

## Return value

`#!cpp true` if the type is primitive, `#!cpp false` otherwise.

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

- [is_structured](is_structured.md) - return whether the type is structured (the complement of this function, for a
  non-discarded view)
- [`BasicJsonType::is_primitive`](../basic_json/is_primitive.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
