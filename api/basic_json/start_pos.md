# <small>nlohmann::basic_json::</small>start_pos

```cpp
#if JSON_DIAGNOSTIC_POSITIONS
constexpr std::size_t start_pos() const noexcept;
#endif
```

Returns the position of the first character in the JSON string from which the value was parsed from.

| JSON type | return value                                   |
|-----------|------------------------------------------------|
| object    | position of the opening `{`                    |
| array     | position of the opening `[`                    |
| string    | position of the opening `"`                    |
| number    | position of the first character                |
| boolean   | position of `t` for `true` and `f` for `false` |
| null      | position of `n`                                |

## Return value

the position of the first character of the value in the parsed JSON string, if the value was created by the
[`parse`](parse.md) function, or `std::string::npos` if the value was constructed otherwise

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Notes

!!! note "Note"

    The function is only available if macro [`JSON_DIAGNOSTIC_POSITIONS`](../macros/json_diagnostic_positions.md) has
    been defined to `#!cpp 1` before including the library header.

!!! warning "Invalidation"

    The returned positions are only valid as long as the JSON value is not changed. The positions are *not* updated
    when the JSON value is changed.

## Examples

??? example "Example"

    ```cpp
    --8<-- "examples/diagnostic_positions.cpp"
    ```
    
    Output:

    ```
    --8<-- "examples/diagnostic_positions.output"
    ```

    The output shows the start/end positions of all the objects and fields in the JSON string.

## See also

- [end_pos](end_pos.md) to access the end position
- [JSON_DIAGNOSTIC_POSITIONS](../macros/json_diagnostic_positions.md) for an overview of the diagnostic positions

## Version history

- Added in version 3.12.0.
