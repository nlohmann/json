# <small>nlohmann::basic_json_view::</small>front

```cpp
basic_json_view front() const;
```

Returns the first element of an array, the first member value of an object, or the value itself if it is primitive
(as for [`BasicJsonType::front()`](../basic_json/front.md), a primitive value is a range of one element).

## Return value

The first element or member value. For a primitive value (number, string, boolean), the value itself.

## Exception safety

Strong exception safety: if an exception is thrown, there are no changes to the view or the document it refers to.

## Exceptions

Throws [`invalid_iterator.214`](../../home/exceptions.md#jsonexceptioninvalid_iterator214) if the view is
[null](is_null.md) or [discarded](is_discarded.md), or if it is an empty array or object.

This exception does not carry a [`JSON_DIAGNOSTICS`](../macros/json_diagnostics.md) path: the view has no
`BasicJsonType` value to point at, so the exception is created without one, even if `BasicJsonType` was built with
`JSON_DIAGNOSTICS` enabled.

## Complexity

Constant.

## Notes

Unlike [`BasicJsonType::front()`](../basic_json/front.md), which has undefined behavior for an empty array or
object, `front()` throws `invalid_iterator.214` in that case -- the same way it already does for `#!json null` and
for a discarded view, where `BasicJsonType::front()` also throws.

## Examples

??? example

    The example below reads only the earliest entry of a build log with `front()`, without materializing the rest
    of the (possibly long) log.

    ```cpp
    --8<-- "examples/basic_json_view__front.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__front.output"
    ```

## See also

- [back](back.md) - access the last element
- [`BasicJsonType::front`](../basic_json/front.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
