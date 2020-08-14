# basic_json::exception

```cpp
class exception : public std::exception;
```

This class is an extension of [`std::exception`](https://en.cppreference.com/w/cpp/error/exception) objects with a
member `id` for exception ids. It is used as the base class for all exceptions thrown by the `basic_json` class. This
class can hence be used as "wildcard" to catch exceptions, see example below.

```plantuml
std::exception <|-- json::exception
json::exception <|-- json::parse_error
json::exception <|-- json::invalid_iterator
json::exception <|-- json::type_error
json::exception <|-- json::out_of_range
json::exception <|-- json::other_error

interface std::exception {}

class json::exception #FFFF00 {
    + const int id
    + const char* what() const
}

class json::parse_error {
    + const std::size_t byte
}
```

Subclasses:

- `parse_error` for exceptions indicating a parse error
- `invalid_iterator` for exceptions indicating errors with iterators
- `type_error` for exceptions indicating executing a member function with a wrong type
- `out_of_range` for exceptions indicating access out of the defined range
- `other_error` for exceptions indicating other library errors

## Member functions

- **what** - returns explanatory string

## Member variables

- **id** - the id of the exception

## Example

??? example

    The following code shows how arbitrary library exceptions can be caught.
    
    ```cpp
    --8<-- "examples/exception.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/exception.output"
    ```

## Version history

- Since version 3.0.0.
