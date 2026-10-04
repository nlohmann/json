# <small>nlohmann::json_sax::</small>end_object

```cpp
virtual bool end_object() = 0;
```

The end of an object was read.

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

- [start_object](start_object.md) - the beginning of an object was read
- [key](key.md) - an object key was read
- [sax_parse](../basic_json/sax_parse.md) - SAX parser

## Version history

- Added in version 3.2.0.
