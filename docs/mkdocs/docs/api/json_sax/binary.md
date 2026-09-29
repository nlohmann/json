# <small>nlohmann::json_sax::</small>binary

```cpp
virtual bool binary(binary_t& val) = 0;
```

A binary value was read.

## Parameters

`val` (in)
:   binary value

## Return value

Whether parsing should proceed.

## Notes

It is safe to move the passed binary value.

## Examples

??? example

    The example below shows how the SAX interface is used.

    ```cpp
    --8<-- "examples/sax_parse__binary.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/sax_parse__binary.output"
    ```

## See also

- [sax_parse](../basic_json/sax_parse.md) - SAX parser
- [SAX Interface](../../features/parsing/sax_interface.md) - the SAX interface article
- [Binary Values](../../features/binary_values.md) - the article on binary values

## Version history

- Added in version 3.8.0.
