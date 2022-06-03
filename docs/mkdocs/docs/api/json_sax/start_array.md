# <small>nlohmann::json_sax::</small>start_array

```cpp
virtual bool start_array(std::size_t elements) = 0;
```

The beginning of an array was read.

## Parameters

`elements` (in)
:   number of object elements or `#!cpp -1` if unknown

## Return value

Whether parsing should proceed.

## Notes

Binary formats may report the number of elements.

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
