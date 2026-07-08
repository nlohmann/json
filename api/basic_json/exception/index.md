# nlohmann::basic_json::exception

```
class exception : public std::exception;
```

This class is an extension of [`std::exception`](https://en.cppreference.com/w/cpp/error/exception) objects with a member `id` for exception ids. It is used as the base class for all exceptions thrown by the `basic_json` class. This class can hence be used as "wildcard" to catch exceptions, see example below.

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

    style json_exception fill:#CCCCFF
```

Subclasses:

- [`parse_error`](https://json.nlohmann.me/api/basic_json/parse_error/index.md) for exceptions indicating a parse error
- [`invalid_iterator`](https://json.nlohmann.me/api/basic_json/invalid_iterator/index.md) for exceptions indicating errors with iterators
- [`type_error`](https://json.nlohmann.me/api/basic_json/type_error/index.md) for exceptions indicating executing a member function with a wrong type
- [`out_of_range`](https://json.nlohmann.me/api/basic_json/out_of_range/index.md) for exceptions indicating access out of the defined range
- [`other_error`](https://json.nlohmann.me/api/basic_json/other_error/index.md) for exceptions indicating other library errors

## Member functions

- **what** - returns explanatory string

## Member variables

- **id** - the id of the exception

## Notes

To have nothrow-copy-constructible exceptions, we internally use `std::runtime_error` which can cope with arbitrary-length error messages. Intermediate strings are built with static functions and then passed to the actual constructor.

## Examples

Example

The following code shows how arbitrary library exceptions can be caught.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    try
    {
        // calling at() for a non-existing key
        json j = {{"foo", "bar"}};
        json k = j.at("non-existing");
    }
    catch (const json::exception& e)
    {
        // output exception information
        std::cout << "message: " << e.what() << '\n'
                  << "exception id: " << e.id << std::endl;
    }
}
```

Output:

```
message: [json.exception.out_of_range.403] key 'non-existing' not found
exception id: 403
```

## See also

[List of exceptions](https://json.nlohmann.me/home/exceptions/index.md)

## Version history

- Since version 3.0.0.
