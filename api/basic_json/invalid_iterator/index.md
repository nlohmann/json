# nlohmann::basic_json::invalid_iterator

```
class invalid_iterator : public exception;
```

This exception is thrown if iterators passed to a library function do not match the expected semantics.

Exceptions have ids 2xx (see [list of iterator errors](https://json.nlohmann.me/home/exceptions/#iterator-errors)).

```
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

## Member functions

- **what** - returns explanatory string

## Member variables

- **id** - the id of the exception

## Examples

Example

The following code shows how a `invalid_iterator` exception can be caught.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

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
                  << "exception id: " << e.id << std::endl;
    }
}
```

Output:

```
message: [json.exception.invalid_iterator.207] cannot use key() for non-object iterators
exception id: 207
```

## See also

- [`exception`](https://json.nlohmann.me/api/basic_json/exception/index.md) for the base class of all exceptions thrown by the library
- [List of iterator errors](https://json.nlohmann.me/home/exceptions/#iterator-errors)
- [`parse_error`](https://json.nlohmann.me/api/basic_json/parse_error/index.md) for exceptions indicating a parse error
- [`type_error`](https://json.nlohmann.me/api/basic_json/type_error/index.md) for exceptions indicating executing a member function with a wrong type
- [`out_of_range`](https://json.nlohmann.me/api/basic_json/out_of_range/index.md) for exceptions indicating access out of the defined range
- [`other_error`](https://json.nlohmann.me/api/basic_json/other_error/index.md) for exceptions indicating other library errors

## Version history

- Since version 3.0.0.
