# <small>nlohmann::basic_json::</small>end_pos

```cpp
#if JSON_DIAGNOSTIC_POSITIONS
constexpr std::size_t end_pos() const noexcept;
#endif
```

Returns the position immediately following the last character of the JSON string from which the value was parsed from.

| JSON type | return value                      |
|-----------|-----------------------------------|
| object    | position after the closing `}`    |
| array     | position after the closing `]`    |
| string    | position after the closing `"`    |
| number    | position after the last character |
| boolean   | position after `e`                |
| null      | position after `l`                |

## Return value

the position of the character _following_ the last character of the given value in the parsed JSON string, if the
value was created by the [`parse`](parse.md) function, or `std::string::npos` if the value was constructed otherwise

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

- [start_pos](start_pos.md) to access the start position
- [JSON_DIAGNOSTIC_POSITIONS](../macros/json_diagnostic_positions.md) for an overview of the diagnostic positions

## Version history

- Added in version 3.12.0.
