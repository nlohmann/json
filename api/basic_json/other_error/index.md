# nlohmann::basic_json::other_error

```
class other_error : public exception;
```

This exception is thrown in case of errors that cannot be classified with the other exception types.

Exceptions have ids 5xx (see [list of other errors](https://json.nlohmann.me/home/exceptions/#further-exceptions)).

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

    style json_other_error fill:#CCCCFF
```

## Member functions

- **what** - returns explanatory string

## Member variables

- **id** - the id of the exception

## Examples

Example

The following code shows how a `other_error` exception can be caught.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace nlohmann::literals;

int main()
{
    try
    {
        // executing a failing JSON Patch operation
        json value = R"({
            "best_biscuit": {
                "name": "Oreo"
            }
        })"_json;
        json patch = R"([{
            "op": "test",
            "path": "/best_biscuit/name",
            "value": "Choco Leibniz"
        }])"_json;
        value.patch(patch);
    }
    catch (const json::other_error& e)
    {
        // output exception information
        std::cout << "message: " << e.what() << '\n'
                  << "exception id: " << e.id << std::endl;
    }
}
```

Output:

```
message: [json.exception.other_error.501] unsuccessful: {"op":"test","path":"/best_biscuit/name","value":"Choco Leibniz"}
exception id: 501
```

## See also

- [`exception`](https://json.nlohmann.me/api/basic_json/exception/index.md) for the base class of all exceptions thrown by the library
- [List of other errors](https://json.nlohmann.me/home/exceptions/#further-exceptions)
- [`parse_error`](https://json.nlohmann.me/api/basic_json/parse_error/index.md) for exceptions indicating a parse error
- [`invalid_iterator`](https://json.nlohmann.me/api/basic_json/invalid_iterator/index.md) for exceptions indicating errors with iterators
- [`type_error`](https://json.nlohmann.me/api/basic_json/type_error/index.md) for exceptions indicating executing a member function with a wrong type
- [`out_of_range`](https://json.nlohmann.me/api/basic_json/out_of_range/index.md) for exceptions indicating access out of the defined range

## Version history

- Since version 3.0.0.
