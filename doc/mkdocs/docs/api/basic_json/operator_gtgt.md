# operator>>(basic_json)

```cpp
std::istream& operator>>(std::istream& i, basic_json& j)
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

- Throws [`parse_error.101`](../../home/exceptions.md#jsonexceptionparse_error101) in case of an unexpected token.
- Throws [`parse_error.102`](../../home/exceptions.md#jsonexceptionparse_error102) if to_unicode fails or surrogate 
  error.
- Throws [`parse_error.103`](../../home/exceptions.md#jsonexceptionparse_error103) if to_unicode fails.

## Complexity

Linear in the length of the input. The parser is a predictive LL(1) parser.

## Notes

A UTF-8 byte order mark is silently ignored.

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

- [parse](parse.md) for a variant with a parser callback function to filter values while parsing

## Version history

- Added in version 1.0.0
