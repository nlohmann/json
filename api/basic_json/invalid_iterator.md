# <small>nlohmann::basic_json::</small>invalid_iterator

```cpp
class invalid_iterator : public exception;
```

This exception is thrown if iterators passed to a library function do not match the expected semantics.

Exceptions have ids 2xx (see [list of iterator errors](../../home/exceptions.md#iterator-errors)).

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

    style json_invalid_iterator fill:#CCCCFF
```

<p class="nj-caption" markdown>Class hierarchy of the library's exceptions; arrows point from a derived class to its
base class, and the highlighted box is `basic_json::invalid_iterator`.</p>

## Member functions

- **what** - returns explanatory string

## Member variables

- **id** - the id of the exception

## Examples

??? example

    The following code shows how a `invalid_iterator` exception can be caught.
    
    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
    int main()
    {
        try
        {
            // calling iterator::key() on non-object iterator
            json j = "string";
            json::iterator it = j.begin();
            auto k = it.key();
        }
        catch (const json::invalid_iterator& e)
        {
            // output exception information
            std::cout << "message: " << e.what() << '\n'
                      << "exception id: " << e.id << '\n';
        }
    }
    
    ```
    
    Output:
    
    ```json
    message: [json.exception.invalid_iterator.207] cannot use key() for non-object iterators
    exception id: 207
    
    ```

## See also

- [`exception`](exception.md) - the base class of all exceptions thrown by the library
- [List of iterator errors](../../home/exceptions.md#iterator-errors) - overview of iterator errors (`invalid_iterator`)
- [`parse_error`](parse_error.md) - exceptions indicating a parse error
- [`type_error`](type_error.md) - exceptions indicating executing a member function with a wrong type
- [`out_of_range`](out_of_range.md) - exceptions indicating access out of the defined range
- [`other_error`](other_error.md) - exceptions indicating other library errors
- [Exceptions](../../home/exceptions.md) - all exceptions and their error codes
- [`JSON_DIAGNOSTICS`](../macros/json_diagnostics.md) - extended exception messages with the path of the failing value

## Version history

- Added in version 3.0.0.
