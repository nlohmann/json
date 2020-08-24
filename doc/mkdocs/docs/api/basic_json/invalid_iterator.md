# basic_json::invalid_iterator

```cpp
class invalid_iterator : public exception;
```

This exception is thrown if iterators passed to a library function do not match the expected semantics.

Exceptions have ids 2xx.

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

class basic_json::invalid_iterator #FFFF00 {}
```

## Member functions

- **what** - returns explanatory string

## Member variables

- **id** - the id of the exception

## Example

??? example

    The following code shows how a `invalid_iterator` exception can be caught.
    
    ```cpp
    --8<-- "examples/invalid_iterator.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/invalid_iterator.output"
    ```

## Version history

- Since version 3.0.0.
