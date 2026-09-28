# <small>nlohmann::basic_json_view::</small>empty

```cpp
bool empty() const noexcept;
```

Checks whether [`size()`](size.md) is `0`, as [`BasicJsonType::empty()`](../basic_json/empty.md) would for the same
value.

## Return value

The return value depends on the type and is defined as follows:

| Value type          | return value    |
|----------------------|-----------------|
| null                  | `#!cpp true`     |
| discarded             | `#!cpp true`     |
| boolean               | `#!cpp false`    |
| string                | `#!cpp false`    |
| number                | `#!cpp false`    |
| object                | `#!cpp object_t::empty()` |
| array                 | `#!cpp array_t::empty()`  |

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

As for [`BasicJsonType::empty()`](../basic_json/empty.md), this does not return whether a string value is empty -- it
is `#!cpp false` for any string, regardless of its length.

## Examples

??? example

    The example below uses [`size()`](size.md) and `empty()` to decide whether a parsed message is worth acting on,
    without materializing it into a `BasicJsonType` value.

    ```cpp
    --8<-- "examples/basic_json_view__size_empty.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__size_empty.output"
    ```

## See also

- [size](size.md) - return the number of elements
- [`BasicJsonType::empty`](../basic_json/empty.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
