# basic_json::is_discarded

```cpp
constexpr bool is_discarded() const noexcept;
```

This function returns true if and only if the JSON value was discarded during parsing with a callback function (see
[`parser_callback_t`](parser_callback_t.md)).
    
## Return value

`#!cpp true` if type is discarded, `#!cpp false` otherwise.

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Notes

This function will always be `#!cpp false` for JSON values after parsing. That is, discarded values can only occur
during parsing, but will be removed when inside a structured value or replaced by null in other cases.

## Example

??? example

    The following code exemplifies `is_discarded()` for all JSON types.
    
    ```cpp
    --8<-- "examples/is_discarded.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/is_discarded.output"
    ```

## Version history

- Added in version 1.0.0.
