# <small>nlohmann::json_sax::</small>key

```cpp
virtual bool key(string_t& val) = 0;
```

An object key was read.

## Parameters

`val` (in)
:   object key

## Return value

Whether parsing should proceed.

## Notes

It is safe to move the passed object key value.

When parsing JSON text, `val` is the decoded object name, not its spelling in the input:

- All escape sequences (`\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r`, `\t`, `\uXXXX`, and surrogate pairs) are
  decoded, and `\uXXXX` escapes are stored as UTF-8. Different spellings of the same name, such as `#!json "/"`
  and `#!json "\/"`, or `#!json "\u00e9"` and `#!json "\u00E9"`, yield identical strings. An escaped `\u0000` yields
  an embedded NUL byte.
- The name is scanned and validated completely before `key` is called. If it contains an invalid escape sequence, an
  unpaired surrogate, a control character, or ill-formed UTF-8, the parse fails with a
  [`parse_error`](../../home/exceptions.md#parse-errors), and `key` is not called for it.
- No Unicode normalization or case conversion is applied: names that differ in any byte are different strings.
- `key` is called before the following `:` is read, so a parse error may still follow for the same member.
- A name that occurs several times in the same object is passed once per occurrence.

For the binary formats, object keys contain no escape sequences. For CBOR, MessagePack, UBJSON, and BSON, `val` holds
the bytes stored in the input, and [`sax_parse`](../basic_json/sax_parse.md) passes them unchanged, without checking them
for valid UTF-8. BON8 encodes characters itself, so an ill-formed name is a parse error and `key` is not called for it.

## Examples

??? example

    The example below shows how the SAX interface is used.

    ```cpp
    --8<-- "examples/sax_parse.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/sax_parse.output"
    ```

## See also

- [`start_object`](start_object.md) - the beginning of an object was read
- [`end_object`](end_object.md) - the end of an object was read
- [`sax_parse`](../basic_json/sax_parse.md) - SAX parser
- [SAX Interface](../../features/parsing/sax_interface.md) - guide to event-based parsing

## Version history

- Added in version 3.2.0.
- The behavior described in the notes above (decoded names, validation before `key` is called, no normalization, `key`
  before the `:` check, one call per duplicate, bytes of binary formats passed unchanged) is the same in all versions
  from 3.2.0 on, and for the `key` event of a [parser callback](../basic_json/parser_callback_t.md) from 3.0.0 on. BSON
  is only supported from version 3.4.0, and BON8 only from version 3.13.0.
