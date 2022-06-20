# <small>nlohmann::json_sax::</small>number_integer

```cpp
virtual bool number_integer(number_integer_t val) = 0;
```

An integer number was read.

## Parameters

`val` (in)
:   integer value

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
