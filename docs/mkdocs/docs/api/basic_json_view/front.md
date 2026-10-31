# <small>nlohmann::basic_json_view::</small>front

```cpp
basic_json_view front() const;
```

Returns the first element of an array, the first member value of an object, or the value itself if it is primitive
(as for [`BasicJsonType::front()`](../basic_json/front.md), a primitive value is a range of one element).

## Return value

The first element or member value. For a primitive value (number, string, boolean), the value itself.

## Exception safety

Strong guarantee: there are no changes to the view or the document it refers to.

## Exceptions

Throws [`invalid_iterator.214`](../../home/exceptions.md#jsonexceptioninvalid_iterator214) if the view is
[null](is_null.md) or [discarded](is_discarded.md), or if it is an empty array or object.

As for `BasicJsonType`, with [`JSON_DIAGNOSTICS`](../macros/json_diagnostics.md) the exception names the JSON Pointer
path of the value within the document, and with [`JSON_DIAGNOSTIC_POSITIONS`](../macros/json_diagnostic_positions.md)
its bytes in the source text (when [`materialize()`](materialize.md) sets them).

## Complexity

Constant.

## Notes

Unlike [`BasicJsonType::front()`](../basic_json/front.md), which has undefined behavior for an empty array or
object, `front()` throws `invalid_iterator.214` for an empty array, an empty object, a null value, or a discarded
view.

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

- [`back`](back.md) - access the last element
- [`BasicJsonType::front`](../basic_json/front.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
