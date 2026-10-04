# <small>nlohmann::basic_json::</small>as_base_class

```cpp
json_base_class_t& as_base_class() noexcept;
const json_base_class_t& as_base_class() const noexcept;
```

Returns a reference to this object as its custom base class [`json_base_class_t`](json_base_class_t.md). No copy is
made.

Since `basic_json` derives from `json_base_class_t`, a member of `basic_json` hides any member of the custom base class
with the same name. This function makes such hidden members accessible again.

## Return value

reference to this object as [`json_base_class_t`](json_base_class_t.md)

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

The function is equivalent to `static_cast<json_base_class_t&>(j)` (or `static_cast<const json_base_class_t&>(j)`).

## Examples

??? example

    The example shows how to use `as_base_class` to access members of the custom base class that are hidden by members
    of `basic_json`.
    
    ```cpp
    --8<-- "examples/as_base_class.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/as_base_class.output"
    ```

## See also

- [json_base_class_t](json_base_class_t.md) - type of the custom base class

## Version history

- Added in version 3.13.0.
