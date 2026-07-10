# <small>nlohmann::</small>operator>>(basic_json)

```cpp
std::istream& operator>>(std::istream& i, basic_json& j);
```

Deserializes an input stream to a JSON value.

## Parameters

`i` (in, out)
:   input stream to read a serialized JSON value from

`j` (in, out)
:   JSON value to write the deserialized input to

## Return value

the stream `i`

## Exceptions

- Throws [`parse_error.101`](../home/exceptions.md#jsonexceptionparse_error101) in case of an unexpected token.

## Complexity

Linear in the length of the input. The parser is a predictive LL(1) parser.

## Notes

A UTF-8 byte order mark is silently ignored.

Invalid Unicode escapes and unpaired surrogates in the input are reported as
[`parse_error.101`](../home/exceptions.md#jsonexceptionparse_error101) with a detailed message.

`operator>>` parses exactly one JSON value and leaves the stream positioned right after it, so it can be called
repeatedly to read a sequence of concatenated JSON values from the same stream:

```cpp
json j1, j2;
input >> j1;  // parses the first value, stream now positioned right after it
input >> j2;  // parses the next value
```

Note this does **not** work for [JSON Lines](../features/parsing/json_lines.md) (newline-delimited JSON) input --
see that page for why and for the recommended alternative.

!!! warning "Deprecation"

    This function replaces function `#!cpp std::istream& operator<<(basic_json& j, std::istream& i)` which has
    been deprecated in version 3.0.0. It will be removed in version 4.0.0. Please replace calls like `#!cpp j << i;`
    with `#!cpp i >> j;`.

## Examples

??? example

    The example below shows how a JSON value is constructed by reading a serialization from a stream.
        
    ```cpp
    --8<-- "examples/operator_deserialize.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/operator_deserialize.output"
    ```

## See also

- [accept](basic_json/accept.md) - check if the input is valid JSON
- [parse](basic_json/parse.md) - deserialize from a compatible input

## Version history

- Added in version 1.0.0.
