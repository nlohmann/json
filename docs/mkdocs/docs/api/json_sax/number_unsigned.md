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
