# <small>nlohmann::basic_json_view::</small>get_string

```cpp
string_view_t get_string() const;
```

Returns the string value as a [`string_view_t`](index.md#member-types), without copying it.

## Return value

The string, as a [`string_view_t`](index.md#member-types) that points either into the document's
[`source()`](../basic_json_document/source.md) text (a string with no escape sequences), or into the document's own
buffer of decoded strings (a string that contains escape sequences, such as `#!json "\n"` or `#!json "\u00e9"`, which
had to be decoded once when the document was parsed).

## Exception safety

Strong exception safety: if an exception is thrown, there are no changes to the view or the document it refers to.

## Exceptions

Throws [`type_error.302`](../../home/exceptions.md#jsonexceptiontype_error302) if the value is not a string; example:
`"type must be string, but is array"`.

This exception does not carry a [`JSON_DIAGNOSTICS`](../macros/json_diagnostics.md) path: the view has no
`BasicJsonType` value to point at, so the exception is created without one, even if `BasicJsonType` was built with
`JSON_DIAGNOSTICS` enabled.

## Complexity

Constant.

## Notes

`basic_json_view` has no `BasicJsonType` value stored anywhere, so unlike `BasicJsonType`, it has no `get_ref()` to
hand out a reference to a stored `string_t`. `get_string()` (equivalently, [`get<string_view_t>()`](get.md)) is the
zero-copy alternative: [`BasicJsonType::get_ref<const string_t&>()`](../basic_json/get_ref.md) is its closest
counterpart, except that it returns a view instead of a reference to a value that must already exist.

The returned [`string_view_t`](index.md#member-types) is valid exactly as long as the view that produced it -- see the
[validity rules](index.md) of `basic_json_view` -- and, for a string with no escapes, for as long as the document's
source text.

## Examples

??? example

    The example below pulls one field out of a JSON text that stands in for a large API response, and shows that no
    `#!cpp std::string` was allocated for it: the returned view still points inside the original buffer. A field that
    contains an escape sequence cannot point into the original text -- it was decoded once into the document's own
    buffer instead -- but still avoids a per-field allocation.

    ```cpp
    --8<-- "examples/basic_json_view__get_string.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__get_string.output"
    ```

## See also

- [get](get.md) - convert the value to a given type (`#!cpp get<string_view_t>()` is equivalent to this function)
- [number_token](number_token.md) - a number's token text, without a copy
- [`BasicJsonType::get_ref`](../basic_json/get_ref.md) - the closest counterpart of `basic_json`

## Version history

- Added in version 3.13.0.
