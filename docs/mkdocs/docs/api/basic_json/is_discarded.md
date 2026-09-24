# <small>nlohmann::basic_json::</small>is_discarded

```cpp
constexpr bool is_discarded() const noexcept;
```

This function returns `#!cpp true` for a JSON value if either:

- the value was discarded during parsing with a callback function (see [`parser_callback_t`](parser_callback_t.md)), or
- the value is the result of parsing invalid JSON with parameter `allow_exceptions` set to `#!cpp false`; see
  [`parse`](parse.md) for more information.

## Return value

`#!cpp true` if type is discarded, `#!cpp false` otherwise.

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Notes

!!! note "Comparisons"

    Discarded values are never compared equal with [`operator==`](operator_eq.md). That is, checking whether a JSON
    value `j` is discarded will only work via:
    
    ```cpp
    j.is_discarded()
    ```
    
    because
    
    ```cpp
    j == json::value_t::discarded
    ```
    
    will always be `#!cpp false`.

!!! note "Removal during parsing with callback functions"

    When a value is discarded by a callback function (see [`parser_callback_t`](parser_callback_t.md)) during parsing,
    then it is removed when it is part of a structured value. For instance, if the second value of an array is discarded,
    instead of `#!json [null, discarded, false]`, the array `#!json [null, false]` is returned. If the top-level value
    itself is discarded by the callback, the `parse` call returns a `#!json null` value.

After a successful parse, this function always returns `#!cpp false`: discarded values can only occur during parsing and
are either removed when inside a structured value or replaced by `#!json null` at the top level. The exception is parsing
with `allow_exceptions` set to `#!cpp false`: a parse error then yields a discarded value for which this function returns
`#!cpp true` (see [`parse`](parse.md)).

## Examples

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
