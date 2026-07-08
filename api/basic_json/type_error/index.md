# nlohmann::basic_json::type_error

```
class type_error : public exception;
```

This exception is thrown in case of a type error; that is, a library function is executed on a JSON value whose type does not match the expected semantics.

Exceptions have ids 3xx (see [list of type errors](https://json.nlohmann.me/home/exceptions/#type-errors)).

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

    style json_type_error fill:#CCCCFF
```

## Member functions

- **what** - returns explanatory string

## Member variables

- **id** - the id of the exception

## Examples

Example

The following code shows how a `type_error` exception can be caught.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    try
    {
        // calling push_back() on a string value
        json j = "string";
        j.push_back("another string");
    }
    catch (const json::type_error& e)
    {
        // output exception information
        std::cout << "message: " << e.what() << '\n'
                  << "exception id: " << e.id << std::endl;
    }
}
```

Output:

```
message: [json.exception.type_error.308] cannot use push_back() with string
exception id: 308
```

## See also

- [`exception`](https://json.nlohmann.me/api/basic_json/exception/index.md) for the base class of all exceptions thrown by the library
- [List of type errors](https://json.nlohmann.me/home/exceptions/#type-errors)
- [`parse_error`](https://json.nlohmann.me/api/basic_json/parse_error/index.md) for exceptions indicating a parse error
- [`invalid_iterator`](https://json.nlohmann.me/api/basic_json/invalid_iterator/index.md) for exceptions indicating errors with iterators
- [`out_of_range`](https://json.nlohmann.me/api/basic_json/out_of_range/index.md) for exceptions indicating access out of the defined range
- [`other_error`](https://json.nlohmann.me/api/basic_json/other_error/index.md) for exceptions indicating other library errors

## Version history

- Since version 3.0.0.
