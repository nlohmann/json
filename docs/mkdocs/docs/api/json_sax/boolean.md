# <small>nlohmann::json_sax::</small>boolean

```cpp
virtual bool boolean(bool val) = 0;
```

A boolean value was read.

## Parameters

`val` (in)
:   boolean value

## Return value

Whether parsing should proceed.

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
