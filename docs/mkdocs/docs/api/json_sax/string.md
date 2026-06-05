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

## Version history

- Added in version 3.2.0.
