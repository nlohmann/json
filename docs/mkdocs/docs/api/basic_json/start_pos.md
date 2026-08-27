# <small>nlohmann::basic_json::</small>start_pos

```cpp
#if JSON_DIAGNOSTIC_POSITIONS
constexpr std::size_t start_pos() const noexcept;
#endif
```

Returns the UTF-8 byte offset of the first character in the JSON text from which the value was parsed.

| JSON type | return value                                   |
|-----------|------------------------------------------------|
| object    | position of the opening `{`                    |
| array     | position of the opening `[`                    |
| string    | position of the opening `"`                    |
| number    | position of the first character                |
| boolean   | position of `t` for `true` and `f` for `false` |
| null      | position of `n`                                |

## Return value

the UTF-8 byte offset of the first character of the value in the parsed JSON text, if the value was created by the
[`parse`](parse.md) function, or `std::string::npos` if the value was constructed otherwise (including via
[`sax_parse`](sax_parse.md) or a binary format parser)

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
    when the JSON value is changed. Assigning, `push_back`, or `erase` leaves parent and remaining sibling positions
    pointing at the original text; newly constructed replacements have `std::string::npos`.

!!! note "Copy, move, and swap"

    Copying a value copies its positions. Moving transfers them and resets the source to `std::string::npos`.
    Swapping two `basic_json` values exchanges positions.

!!! note "Wide strings"

    Positions from `parse(std::wstring)` / `u16string` / `u32string` index the transcoded UTF-8 byte stream, not the
    original wide string.

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
