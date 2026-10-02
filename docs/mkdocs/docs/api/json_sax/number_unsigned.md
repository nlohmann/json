# <small>nlohmann::json_sax::</small>number_unsigned

```cpp
virtual bool number_unsigned(number_unsigned_t val) = 0;
```

An unsigned integer number was read.

## Parameters

`val` (in)
:   unsigned integer value

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

- [number_integer](number_integer.md) - an integer number was read
- [number_float](number_float.md) - a floating-point number was read
- [sax_parse](../basic_json/sax_parse.md) - SAX parser

## Version history

- Added in version 3.2.0.
