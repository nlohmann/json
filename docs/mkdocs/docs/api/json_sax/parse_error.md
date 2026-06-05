# <small>nlohmann::json_sax::</small>parse_error

```cpp
virtual bool parse_error(std::size_t position,
                         const std::string& last_token,
                         const detail::exception& ex) = 0;
```

A parse error occurred.

## Parameters

`position` (in)
:   the position in the input where the error occurs

`last_token` (in)
:   the last read token

`ex` (in)
:   an exception object describing the error

## Return value

Whether parsing should proceed (**must return `#!cpp false`**).

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
