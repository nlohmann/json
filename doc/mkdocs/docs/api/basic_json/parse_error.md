# basic_json::parse_error

```cpp
class parse_error : public exception;
```

This exception is thrown by the library when a parse error occurs. Parse errors can occur during the deserialization of
JSON text, BSON, CBOR, MessagePack, UBJSON, as well as when using JSON Patch.

Exceptions have ids 1xx.

```plantuml
std::exception <|-- basic_json::exception
basic_json::exception <|-- basic_json::parse_error
basic_json::exception <|-- basic_json::invalid_iterator
basic_json::exception <|-- basic_json::type_error
basic_json::exception <|-- basic_json::out_of_range
basic_json::exception <|-- basic_json::other_error

interface std::exception {}

class basic_json::exception {
    + const int id
    + const char* what() const
}

class basic_json::parse_error #FFFF00 {
    + const std::size_t byte
}
```

## Member functions

- **what** - returns explanatory string

## Member variables

- **id** - the id of the exception
- **byte** - byte index of the parse error

## Note

For an input with _n_ bytes, 1 is the index of the first character and _n_+1 is the index of the terminating null byte
or the end of file. This also holds true when reading a byte vector for binary formats.

## Example

??? example

    The following code shows how a `parse_error` exception can be caught.
    
    ```cpp
    --8<-- "examples/parse_error.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/parse_error.output"
    ```

## Version history

- Since version 3.0.0.
