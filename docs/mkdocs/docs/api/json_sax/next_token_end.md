# <small>nlohmann::json_sax::</small>next_token_end

Informs the sax parser about the end of the next element.
There are two possible signatures for this method:

1. 
```cpp
void next_token_end(std::size_t pos);
```
This version is called with the byte position after the next element ends.
This version also works when parsing binary formats such as [msgpack](../basic_json/input_format_t.md).

2. 
```cpp
void next_token_end(const nlohmann::position_t& p)
```
This version is called with the [detailed parser position information](../position_t/index.md) after the last character of the next element was parsed.
This version only available when calling `nlohmann::json::sax_parse` with `nlohmann::json::input_format_t::json` and takes precedence.

## Parameters
1. 
`pos` (in)
:   Byte position one after the next elements last byte.
2. 
`p` (in)
:   [Detailed parser position information](../position_t/index.md) after the last char of the next element was parsed.

## Notes

Implementing either version is optional, and no function is called if neither version of `next_token_end` is available in the sax parser.

It is recommended, but not required, to also implement [next_token_start](next_token_start.md).

## Examples

??? example

    The example below shows a SAX parser using the first version of this method to log the location.

    ```cpp
    --8<-- "examples/sax_parse_with_src_location.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/sax_parse_with_src_location.output"
    ```

??? example

    The example below shows a SAX parser using the second version of this method and
    storing the location information in each json node using a [base class](../basic_json/json_base_class_t.md) for `nlohmann::json` as customization point.

    ```cpp
    --8<-- "examples/sax_parse_with_src_location_in_json.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/sax_parse_with_src_location_in_json.output"
    ```
## Version history

- Added in version ???.???.???.
