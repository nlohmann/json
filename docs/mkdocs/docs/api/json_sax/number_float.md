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
