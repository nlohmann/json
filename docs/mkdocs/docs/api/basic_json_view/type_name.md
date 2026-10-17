# <small>nlohmann::basic_json_view::</small>type_name

```cpp
const char* type_name() const noexcept;
```

Returns the type name as string to be used in error messages -- usually to indicate that a function was called on a
wrong JSON type. Identical to [`BasicJsonType::type_name()`](../basic_json/type_name.md), including the extra
`#!cpp "discarded"` return value for a [discarded](is_discarded.md) view (`BasicJsonType::type_name()` produces the
same string for a discarded `BasicJsonType` value).

## Return value

a string representation of the type ([`value_t`](../basic_json/value_t.md)):

| Value type                                         | return value  |
|-----------------------------------------------------|---------------|
| `#!json null`                                        | `"null"`      |
| boolean                                              | `"boolean"`   |
| string                                               | `"string"`    |
| number (integer, unsigned integer, floating-point)   | `"number"`    |
| object                                               | `"object"`    |
| array                                                | `"array"`     |
| discarded                                            | `"discarded"` |

`type_name()` never returns `#!cpp "binary"`, since a JSON text has no binary values (see
[`is_binary()`](is_binary.md)); it also never returns `#!cpp "invalid"`, since a view's `#!cpp kind` always comes
from a value the parser actually produced.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Examples

??? example

    The example below reports why some parsed messages were rejected, using only `type_name()` -- no
    `BasicJsonType` value is ever built for the ones that are wrong, and the message text matches what
    [`BasicJsonType::type_name()`](../basic_json/type_name.md) would produce for the same value.

    ```cpp
    --8<-- "examples/basic_json_view__type_name.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__type_name.output"
    ```

## See also

- [type](type.md) - return the type of the value
- [`BasicJsonType::type_name`](../basic_json/type_name.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
