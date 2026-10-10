# <small>nlohmann::basic_json_view::</small>number_token

```cpp
string_view_t number_token() const;
```

Returns the number exactly as it appears in the source text, without parsing or rounding it.

## Return value

The number's token text, as a [`string_view_t`](index.md#member-types) into the document's
[`source()`](../basic_json_document/source.md) text -- for example `#!cpp "1.50"`, `#!cpp "1E2"`, `#!cpp "-0"`, or an
integer literal with more digits than any number type holds (such as a 30-digit integer, which [`get<T>()`](get.md)
and [`materialize()`](materialize.md) can only represent approximately, as a `number_float_t`).

## Exception safety

Strong exception safety: if an exception is thrown, there are no changes to the view or the document it refers to.

## Exceptions

Throws [`type_error.302`](../../home/exceptions.md#jsonexceptiontype_error302) if the value is not a number; example:
`"type must be number, but is string"`.

This exception does not carry a [`JSON_DIAGNOSTICS`](../macros/json_diagnostics.md) path: the view has no
`BasicJsonType` value to point at, so the exception is created without one, even if `BasicJsonType` was built with
`JSON_DIAGNOSTICS` enabled.

## Complexity

Constant.

## Notes

`BasicJsonType` has no counterpart to this function: once a number is parsed into `number_integer_t`,
`number_unsigned_t`, or `number_float_t`, its original textual form (leading zeros aside, which are already rejected
by the grammar; trailing zeros in the fraction; the case and sign of the exponent; ...) is gone. `number_token()` is
useful precisely where that form must survive -- a price or an identifier that must be reproduced exactly, or a
number too large for any of `BasicJsonType`'s number types to hold without loss.

The returned [`string_view_t`](index.md#member-types) always points into the document's
[`source()`](../basic_json_document/source.md) text -- numbers are never decoded into the document's separate string
buffer -- and is valid exactly as long as that text is, see the [validity rules](index.md) of `basic_json_view`.

## Examples

??? example

    The example below keeps a price and an order ID exactly as they were written in an incoming order, where
    converting them with [`get<T>()`](get.md) would lose information: the price picks up floating-point rounding, and
    the order ID -- more digits than a 64-bit integer holds -- can only be approximated as a `#!cpp double` once
    `#!cpp materialize()`d.

    ```cpp
    --8<-- "examples/basic_json_view__number_token.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__number_token.output"
    ```

## See also

- [get](get.md) - convert the value to a given type
- [get_string](get_string.md) - the string, without a copy
- [`BasicJsonType::number_integer_t`](../basic_json/number_integer_t.md),
  [`number_unsigned_t`](../basic_json/number_unsigned_t.md), [`number_float_t`](../basic_json/number_float_t.md) - the
  number types `#!cpp get<T>()` and `materialize()` convert into

## Version history

- Added in version 3.13.0.
