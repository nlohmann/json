# <small>nlohmann::json_sax::</small>string

```cpp
virtual bool string(string_t& val) = 0;
```

A string value was read.

## Parameters

`val` (in)
:   string value

## Return value

Whether parsing should proceed.

## Notes

It is safe to move the passed string value.

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

- [sax_parse](../basic_json/sax_parse.md) - SAX parser
- [SAX Interface](../../features/parsing/sax_interface.md) - the SAX interface article

## Version history

- Added in version 3.2.0.
