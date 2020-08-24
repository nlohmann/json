# basic_json::other_error

```cpp
class other_error : public exception;
```

This exception is thrown in case of errors that cannot be classified with the other exception types.

Exceptions have ids 5xx.

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

class basic_json::parse_error {
    + const std::size_t byte
}

class basic_json::other_error #FFFF00 {}
```

## Member functions

- **what** - returns explanatory string

## Member variables

- **id** - the id of the exception

## Example

??? example

    The following code shows how a `other_error` exception can be caught.
    
    ```cpp
    --8<-- "examples/other_error.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/other_error.output"
    ```

## Version history

- Since version 3.0.0.
