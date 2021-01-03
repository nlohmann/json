# <small>nlohmann::basic_json::</small>operator value_t

```cpp
constexpr operator value_t() const noexcept;
```

Return the type of the JSON value as a value from the [`value_t`](value_t.md) enumeration.
    
## Return value

the type of the JSON value

| Value type                | return value               |
|---------------------------|----------------------------|
| `#!json null`             | `value_t::null`            |
| boolean                   | `value_t::boolean`         |
| string                    | `value_t::string`          |
| number (integer)          | `value_t::number_integer`  |
| number (unsigned integer) | `value_t::number_unsigned` |
| number (floating-point)   | `value_t::number_float`    |
| object                    | `value_t::object`          |
| array                     | `value_t::array`           |
| binary                    | `value_t::binary`          |
| discarded                 | `value_t::discarded`       |

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Examples

??? example

    The following code exemplifies `operator value_t()` for all JSON types.
    
    ```cpp
    --8<-- "examples/operator__value_t.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/operator__value_t.output"
    ```

## Version history

- Added in version 1.0.0.
- Added unsigned integer type in version 2.0.0.
- Added binary type in version 3.8.0.
