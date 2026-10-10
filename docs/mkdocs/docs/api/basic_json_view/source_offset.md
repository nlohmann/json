# <small>nlohmann::basic_json_view::</small>source_offset

```cpp
std::size_t source_offset() const noexcept;
```

Returns the byte offset of this value in the document's [`source()`](../basic_json_document/source.md) text, without
materializing anything.

## Return value

- For a string with no escapes, a number, `#!json true`/`#!json false`/`#!json null`, an array, or an object: the
  byte offset of the first byte of the value's token (for a string: the first byte after the opening quote) in
  [`source()`](../basic_json_document/source.md).
- `#!cpp static_cast<std::size_t>(-1)` for a [discarded](is_discarded.md) view, and for a string that contains
  escapes -- such a string was decoded once into the document's own buffer, so there is no single byte range in
  `source()` left to point at.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

This is a raw offset, not a length: the API does not (yet) expose how many bytes the token occupies in the source
text, so `source_offset()` alone is enough to report *where* a value came from (for an error message, for syntax
highlighting, ...) but not to slice its exact text back out of [`source()`](../basic_json_document/source.md) for a
string, whose token length is not the same as its decoded [`size()`](size.md).

## Examples

??? example

    ```cpp
    --8<-- "examples/basic_json_view__source_offset.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__source_offset.output"
    ```

## See also

- [source](../basic_json_document/source.md) - the parsed text
- [is_string](is_string.md) - return whether the value is a string

## Version history

- Added in version 3.13.0.
