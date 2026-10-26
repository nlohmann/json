# <small>nlohmann::basic_json::</small>parse_error

```cpp
class parse_error : public exception;
```

The library throws this exception when a parse error occurs. Parse errors can occur during the deserialization of
JSON text, BJData, BON8, BSON, CBOR, MessagePack, UBJSON, as well as when using JSON Patch.

Member `byte` holds the byte index of the last read character in the input file (see note below).

Exceptions have ids 1xx (see [list of parse errors](../../home/exceptions.md#parse-errors)).

```mermaid
classDiagram
  direction LR
  
    class std_exception ["std::exception"] {
        <<interface>>
    }

    class json_exception ["basic_json::exception"] {
        +const int id
        +const char* what() const
    }
    
    class json_parse_error ["basic_json::parse_error"] {
        +const std::size_t byte
    }

    class json_invalid_iterator ["basic_json::invalid_iterator"]
    class json_type_error ["basic_json::type_error"]
    class json_out_of_range ["basic_json::out_of_range"]
    class json_other_error ["basic_json::other_error"]

    std_exception <|-- json_exception
    json_exception <|-- json_parse_error
    json_exception <|-- json_invalid_iterator
    json_exception <|-- json_type_error
    json_exception <|-- json_out_of_range
    json_exception <|-- json_other_error

    style json_parse_error fill:#CCCCFF
```

<p class="nj-caption" markdown>Class hierarchy of the library's exceptions; arrows point from a derived class to its
base class, and the highlighted box is `basic_json::parse_error`.</p>

## Member functions

- **what** - returns explanatory string

## Member variables

- **id** - the id of the exception
- **byte** - byte index of the parse error

## Notes

For an input with <i>n</i> bytes, 1 is the index of the first character and <i>n</i>+1 is the index of the terminating null byte
or the end of file. This also holds true when reading a byte vector for binary formats.

## Examples

??? example

    The following code shows how a `parse_error` exception can be caught.
    
    ```cpp
    --8<-- "examples/parse_error.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/parse_error.output"
    ```

## See also

- [`exception`](exception.md) - the base class of all exceptions thrown by the library
- [List of parse errors](../../home/exceptions.md#parse-errors) - overview of parse errors (`parse_error`)
- [`invalid_iterator`](invalid_iterator.md) - exceptions indicating errors with iterators
- [`type_error`](type_error.md) - exceptions indicating executing a member function with a wrong type
- [`out_of_range`](out_of_range.md) - exceptions indicating access out of the defined range
- [`other_error`](other_error.md) - exceptions indicating other library errors
- [Parsing and Exceptions](../../features/parsing/parse_exceptions.md) - handling parse errors and locating them in the input
- [Working Without Exceptions](../../features/no_exceptions.md) - error handling when exceptions are disabled

## Version history

- Added in version 3.0.0.
