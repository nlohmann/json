# <small>nlohmann::json_sax::</small>end_array

```cpp
virtual bool end_array() = 0;
```

The end of an array was read.

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

- [start_array](start_array.md) - the beginning of an array was read
- [sax_parse](../basic_json/sax_parse.md) - SAX parser

## Version history

- Added in version 3.2.0.
