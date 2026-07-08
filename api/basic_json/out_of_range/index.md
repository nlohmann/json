# nlohmann::basic_json::out_of_range

```
class out_of_range : public exception;
```

This exception is thrown in case a library function is called on an input parameter that exceeds the expected range, for instance, in the case of array indices or nonexisting object keys.

Exceptions have ids 4xx (see [list of out-of-range errors](https://json.nlohmann.me/home/exceptions/#out-of-range)).

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

    style json_out_of_range fill:#CCCCFF
```

## Member functions

- **what** - returns explanatory string

## Member variables

- **id** - the id of the exception

## Examples

Example

The following code shows how a `out_of_range` exception can be caught.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    try
    {
        // calling at() for an invalid index
        json j = {1, 2, 3, 4};
        j.at(4) = 10;
    }
    catch (const json::out_of_range& e)
    {
        // output exception information
        std::cout << "message: " << e.what() << '\n'
                  << "exception id: " << e.id << std::endl;
    }
}
```

Output:

```
message: [json.exception.out_of_range.401] array index 4 is out of range
exception id: 401
```

## See also

- [`exception`](https://json.nlohmann.me/api/basic_json/exception/index.md) for the base class of all exceptions thrown by the library
- [List of out-of-range errors](https://json.nlohmann.me/home/exceptions/#out-of-range)
- [`parse_error`](https://json.nlohmann.me/api/basic_json/parse_error/index.md) for exceptions indicating a parse error
- [`invalid_iterator`](https://json.nlohmann.me/api/basic_json/invalid_iterator/index.md) for exceptions indicating errors with iterators
- [`type_error`](https://json.nlohmann.me/api/basic_json/type_error/index.md) for exceptions indicating executing a member function with a wrong type
- [`other_error`](https://json.nlohmann.me/api/basic_json/other_error/index.md) for exceptions indicating other library errors

## Version history

- Since version 3.0.0.
