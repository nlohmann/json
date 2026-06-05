# <small>nlohmann::basic_json::</small>type_error

```cpp
class type_error : public exception;
```

This exception is thrown in case of a type error; that is, a library function is executed on a JSON value whose type
does not match the expected semantics.

Exceptions have ids 3xx (see [list of type errors](../../home/exceptions.md#type-errors)).

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

    style json_type_error fill:#CCCCFF
```

## Member functions

- **what** - returns explanatory string

## Member variables

- **id** - the id of the exception

## Examples

??? example

    The following code shows how a `type_error` exception can be caught.
    
    ```cpp
    --8<-- "examples/type_error.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/type_error.output"
    ```

## See also

- [List of type errors](../../home/exceptions.md#type-errors)
- [`parse_error`](parse_error.md) for exceptions indicating a parse error
- [`invalid_iterator`](invalid_iterator.md) for exceptions indicating errors with iterators
- [`out_of_range`](out_of_range.md) for exceptions indicating access out of the defined range
- [`other_error`](other_error.md) for exceptions indicating other library errors

## Version history

- Since version 3.0.0.
