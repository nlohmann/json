# <small>nlohmann::json_sax::</small>next_token_start

Informs the sax parser about the start of the next element.
There are two possible signatures for this method:

1. 
```cpp
void next_token_start(std::size_t pos);
```
This version is called with the byte position where the next element starts. This version also works when parsing binary formats such as [msgpack](../basic_json/input_format_t.md).

2. 
```cpp
template<class BasicJsonType, class InputAdapterType>
void next_token_start(const nlohmann::detail::lexer<BasicJsonType, InputAdapterType>& lex)
```
This version is called with the lexer after the first character of the next element was parsed. The lexer can provide additional information about the current parse context. This version only available when calling `nlohmann::json::sax_parse` with `nlohmann::json::input_format_t::json` and takes precedence.

## Template parameters
1. 
(none)
2. 
`BasicJsonType`
:   a specialization of `basic_json` used by the lexer. (Leave this as a template parameter)
`InputAdapterType`
:   The input adapter used by the lexer. (Leave this as a template parameter)

## Parameters
1. 
`pos` (in)
:   Byte position where the next element starts.
2. 
`lex` (in)
:   Lexer after the first char of the next element was parsed.

## Notes

Implementing either version is optional, and no function is called if neither version of `next_token_start` is available in the sax parser.

It is recommended, but not required, to also implement [next_token_end](next_token_end.md).

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

    The example below shows a SAX parser using the second version of this method and storing the location information in each json node using a [base class](../basic_json/json_base_class_t.md) for `nlohmann::json` as customization point.

    ```cpp
    --8<-- "examples/sax_parse_with_src_location_in_json.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/sax_parse_with_src_location_in_json.output"
    ```
## Version history

- Added in version ???.???.???.
