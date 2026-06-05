# <small>nlohmann::basic_json::</small>dump

```cpp
string_t dump(const int indent = -1,
              const char indent_char = ' ',
              const bool ensure_ascii = false,
              const error_handler_t error_handler = error_handler_t::strict) const;
```

Serialization function for JSON values. The function tries to mimic Python's
[`json.dumps()` function](https://docs.python.org/2/library/json.html#json.dump), and currently supports its `indent`
and `ensure_ascii` parameters.
    
## Parameters

`indent` (in)
:   If `indent` is nonnegative, then array elements and object members will be pretty-printed with that indent level. An
    indent level of `0` will only insert newlines. `-1` (the default) selects the most compact representation.

`indent_char` (in)
:   The character to use for indentation if `indent` is greater than `0`. The default is ` ` (space).

`ensure_ascii` (in)
:   If `ensure_ascii` is true, all non-ASCII characters in the output are escaped with `\uXXXX` sequences, and the
    result consists of ASCII characters only.

`error_handler` (in)
:   how to react on decoding errors; there are three possible values (see [`error_handler_t`](error_handler_t.md):
    `strict` (throws and exception in case a decoding error occurs; default), `replace` (replace invalid UTF-8 sequences
    with U+FFFD), and `ignore` (ignore invalid UTF-8 sequences during serialization; all bytes are copied to the output
    unchanged)).
    
## Return value

string containing the serialization of the JSON value

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes to any JSON value.

## Exceptions

Throws [`type_error.316`](../../home/exceptions.md#jsonexceptiontype_error316) if a string stored inside the JSON value
is not UTF-8 encoded and `error_handler` is set to `strict`

## Complexity

Linear.

## Notes

Binary values are serialized as an object containing two keys:

- "bytes": an array of bytes as integers
- "subtype": the subtype as integer or `#!json null` if the binary has no subtype

## Examples

??? example

    The following example shows the effect of different `indent`, `indent_char`, and `ensure_ascii` parameters to the
    result of the serialization.

    ```cpp
    --8<-- "examples/dump.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/dump.output"
    ```

## Version history

- Added in version 1.0.0.
- Indentation character `indent_char`, option `ensure_ascii` and exceptions added in version 3.0.0.
- Error handlers added in version 3.4.0.
- Serialization of binary values added in version 3.8.0.
