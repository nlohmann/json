# <small>nlohmann::json_sax::</small>number_float

```cpp
virtual bool number_float(number_float_t val, const string_t& s) = 0;
```

A floating-point number was read.

## Parameters

`val` (in)
:   floating-point value

`s` (in)
:   string representation of the original input

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
- [number_unsigned](number_unsigned.md) - an unsigned integer number was read
- [sax_parse](../basic_json/sax_parse.md) - SAX parser

## Version history

- Added in version 3.2.0.
