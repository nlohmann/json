# <small>nlohmann::json_sax::</small>end_object

```cpp
virtual bool end_object() = 0;
```

The end of an object was read.

## Return value

Whether parsing should proceed.

## Examples

??? example

    .The example below shows how the SAX interface is used.

    ```cpp
    --8<-- "examples/sax_parse.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/sax_parse.output"
    ```

## Version history

- Added in version 3.2.0.
