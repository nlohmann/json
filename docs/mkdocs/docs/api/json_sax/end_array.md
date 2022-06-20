# <small>nlohmann::json_sax::</small>end_array

```cpp
virtual bool end_array() = 0;
```

The end of an array was read.

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
