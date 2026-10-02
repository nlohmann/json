# <small>nlohmann::basic_json_view::</small>is_discarded

```cpp
bool is_discarded() const noexcept;
```

Returns whether this view is invalid, i.e. does not refer to a value. This is the case for a default-constructed
view (see [(constructor)](basic_json_view.md)), and for [`root()`](../basic_json_document/root.md) of a document
that is itself [discarded](../basic_json_document/is_discarded.md) -- in particular, the root of a failed
[`parse()`](../basic_json_document/parse.md) with `allow_exceptions` set to `#!cpp false`.

## Return value

`#!cpp true` if the view is discarded, `#!cpp false` otherwise.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

`#!cpp v.is_discarded()` and `#!cpp !static_cast<bool>(v)` are equivalent; use whichever reads better at the call
site.

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

- [operator bool](operator_bool.md) - return whether the view refers to a value
- [(constructor)](basic_json_view.md) - the default constructor creates a discarded view
- [is_discarded (basic_json_document)](../basic_json_document/is_discarded.md) - return whether the last parse failed
- [`BasicJsonType::is_discarded`](../basic_json/is_discarded.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
