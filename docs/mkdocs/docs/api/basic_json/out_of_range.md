# <small>nlohmann::basic_json::</small>out_of_range

```cpp
class out_of_range : public exception;
```

This exception is thrown in case a library function is called on an input parameter that exceeds the expected range, for
instance, in the case of array indices or nonexisting object keys.

Exceptions have ids 4xx (see [list of out-of-range errors](../../home/exceptions.md#out-of-range)).

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

    style json_out_of_range fill:#CCCCFF
```

<p class="nj-caption" markdown>Class hierarchy of the library's exceptions; arrows point from a derived class to its
base class, and the highlighted box is `basic_json::out_of_range`.</p>

## Member functions

- **what** - returns explanatory string

## Member variables

- **id** - the id of the exception

## Examples

??? example

    The following code shows how a `out_of_range` exception can be caught.
    
    ```cpp
    --8<-- "examples/out_of_range.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/out_of_range.output"
    ```

## See also

- [`exception`](exception.md) - the base class of all exceptions thrown by the library
- [List of out-of-range errors](../../home/exceptions.md#out-of-range) - overview of out-of-range errors
  (`out_of_range`)
- [`parse_error`](parse_error.md) - exceptions indicating a parse error
- [`invalid_iterator`](invalid_iterator.md) - exceptions indicating errors with iterators
- [`type_error`](type_error.md) - exceptions indicating executing a member function with a wrong type
- [`other_error`](other_error.md) - exceptions indicating other library errors
- [Exceptions](../../home/exceptions.md) - all exceptions and their error codes
- [`JSON_DIAGNOSTICS`](../macros/json_diagnostics.md) - extended exception messages with the path of the failing value

## Version history

- Added in version 3.0.0.
