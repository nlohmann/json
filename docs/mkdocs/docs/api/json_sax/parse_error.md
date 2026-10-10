# <small>nlohmann::json_sax::</small>parse_error

```cpp
virtual bool parse_error(std::size_t position,
                         const std::string& last_token,
                         const detail::exception& ex) = 0;
```

A parse error occurred.

## Parameters

`position` (in)
:   the position in the input where the error occurs

`last_token` (in)
:   the last read token

`ex` (in)
:   an exception object describing the error

## Return value

Whether to recover from the error:

- `#!cpp false` stops parsing.
- `#!cpp true` recovers from the error: the error is repaired and parsing continues. If that is not possible, which
  happens in the binary formats when the end of the item with the error is unknown, the value read so far is completed
  and parsing stops. See [error recovery](../../features/parsing/error_recovery.md) for how errors are repaired.

Either way, [`sax_parse`](../basic_json/sax_parse.md) returns `#!cpp false`.

## Examples

??? example "Example: (1) the SAX interface"

    The example below shows how the SAX interface is used.

    ```cpp
    --8<-- "examples/sax_parse.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/sax_parse.output"
    ```

??? example "Example: (2) recovering from errors"

    The example below shows how a SAX parser recovers from errors.

    ```cpp
    --8<-- "examples/sax_parse__error_recovery.cpp"
    ```
    
    Output:
    
    ```
    --8<-- "examples/sax_parse__error_recovery.output"
    ```

## See also

- [sax_parse](../basic_json/sax_parse.md) - SAX parser
- [Parsing and Exceptions](../../features/parsing/parse_exceptions.md) - the article on handling parse errors without
  exceptions
- [Error Recovery](../../features/parsing/error_recovery.md) - the article on recovering from parse errors

## Version history

- Added in version 3.2.0.
- Returning `#!cpp true` recovers from the error since version 3.13.0; before, parsing stopped, but the result of
  [`sax_parse`](../basic_json/sax_parse.md) could be wrong.
