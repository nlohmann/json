# JSON_DIAGNOSTIC_POSITIONS

```cpp
#define JSON_DIAGNOSTIC_POSITIONS /* value */
```

This macro enables position diagnostics for generated JSON objects.

When enabled, two new member functions [`start_pos()`](../basic_json/start_pos.md) and
[`end_pos()`](../basic_json/end_pos.md) are added to [`basic_json`](../basic_json/index.md) values. If the value was
created by calling the[`parse`](../basic_json/parse.md) function, then these functions allow to query the byte positions
of the value in the input it was parsed from. In case the value was constructed by other means, `std::string::npos` is
returned.

[`start_pos()`](../basic_json/start_pos.md) returns the position of the first character of a given value in the original
JSON string, while [`end_pos()`](../basic_json/end_pos.md) returns the position of the character _following_ the last
character. For objects and arrays, the first and last characters correspond to the opening or closing braces/brackets,
respectively. For primitive values, the first and last character represent the opening and closing quotes (strings) or
the first and last character of the field's numerical or predefined value (`true`, `false`, `null`), respectively.

| JSON type | return value [`start_pos()`](../basic_json/start_pos.md) | return value [`end_pos()`](../basic_json/end_pos.md) |
|-----------|----------------------------------------------------------|------------------------------------------------------|
| object    | position of the opening `{`                              | position after the closing `}`                       |
| array     | position of the opening `[`                              | position after the closing `]`                       |
| string    | position of the opening `"`                              | position after the closing `"`                       |
| number    | position of the first character                          | position after the last character                    |
| boolean   | position of `t` for `true` and `f` for `false`           | position after `e`                                   |
| null      | position of `n`                                          | position after `l`                                   |

Given the above, [`end_pos()`](../basic_json/end_pos.md)` - `[`start_pos()`](../basic_json/start_pos.md) for a JSON
value provides the length of the parsed JSON string for that value, including the opening or closing braces, brackets,
or quotes.

Note that enabling this macro increases the size of every JSON value by two `std::size_t` fields and adds slight runtime
overhead to parsing, copying JSON value objects, and the generation of error messages for exceptions. It also causes
these values to be reported in those error messages.

## Default definition

The default value is `0` (position diagnostics are switched off).

```cpp
#define JSON_DIAGNOSTIC_POSITIONS 0
```

When the macro is not defined, the library will define it to its default value.

## Notes

!!! note "CMake option"

    Diagnostic positions can also be controlled with the CMake option
    [`JSON_Diagnostic_Positions`](../../integration/cmake.md#json_diagnostic_positions) (`OFF` by default)
    which defines `JSON_DIAGNOSTIC_POSITIONS` accordingly.

!!! note "Availability"

    Diagnostic positions are only available if the value was created by the [`parse`](../basic_json/parse.md) function.
    The [`sax_parse`](../basic_json/sax_parse.md) function or all other means to create a JSON value **do not** set the
    diagnostic positions and [`start_pos()`](../basic_json/start_pos.md) and [`end_pos()`](../basic_json/end_pos.md)
    will only return `std::string::npos` for these values.

!!! warning "Invalidation"

    The returned positions are only valid as long as the JSON value is not changed. The positions are *not* updated
    when the JSON value is changed.

## Examples

??? example "Example: retrieving positions"

    ```cpp
    --8<-- "examples/diagnostic_positions.cpp"
    ```
    
    Output:

    ```
    --8<-- "examples/diagnostic_positions.output"
    ```

    The output shows the start/end positions of all the objects and fields in the JSON string.

??? example "Example 2: using only diagnostic positions in exceptions"

    ```cpp
    --8<-- "examples/diagnostic_positions_exception.cpp"
    ```
    
    Output:

    ```
    --8<-- "examples/diagnostic_positions_exception.output"
    ```

        The output shows the exception with start/end positions only.

??? example "Example 3: using extended diagnostics with positions enabled in exceptions"

    ```cpp
    --8<-- "examples/diagnostics_extended_positions.cpp"
    ```
    
    Output:

    ```
    --8<-- "examples/diagnostics_extended_positions.output"
    ```
    
        The output shows the exception with diagnostic path info and start/end positions.

## See also

- [:simple-cmake: JSON_Diagnostic_Positions](../../integration/cmake.md#json_diagnostic_positions) - CMake option to control the macro
- [JSON_DIAGNOSTICS](json_diagnostics.md) - macro to control extended diagnostics

## Version history

- Added in version 3.12.0.
