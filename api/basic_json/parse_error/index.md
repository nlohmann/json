# nlohmann::basic_json::parse_error

```
class parse_error : public exception;
```

The library throws this exception when a parse error occurs. Parse errors can occur during the deserialization of JSON text, BSON, CBOR, MessagePack, UBJSON, as well as when using JSON Patch.

Member `byte` holds the byte index of the last read character in the input file (see note below).

Exceptions have ids 1xx (see [list of parse errors](https://json.nlohmann.me/home/exceptions/#parse-errors)).

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

    style json_parse_error fill:#CCCCFF
```

## Member functions

- **what** - returns explanatory string

## Member variables

- **id** - the id of the exception
- **byte** - byte index of the parse error

## Notes

For an input with n bytes, 1 is the index of the first character and n+1 is the index of the terminating null byte or the end of file. This also holds true when reading a byte vector for binary formats.

## Examples

Example

The following code shows how a `parse_error` exception can be caught.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    try
    {
        // parsing input with a syntax error
        json::parse("[1,2,3,]");
    }
    catch (const json::parse_error& e)
    {
        // output exception information
        std::cout << "message: " << e.what() << '\n'
                  << "exception id: " << e.id << '\n'
                  << "byte position of error: " << e.byte << std::endl;
    }
}
```

Output:

```
message: [json.exception.parse_error.101] parse error at line 1, column 8: syntax error while parsing value - unexpected ']'; expected '[', '{', or a literal
exception id: 101
byte position of error: 8
```

## See also

- [`exception`](https://json.nlohmann.me/api/basic_json/exception/index.md) for the base class of all exceptions thrown by the library
- [List of parse errors](https://json.nlohmann.me/home/exceptions/#parse-errors)
- [`invalid_iterator`](https://json.nlohmann.me/api/basic_json/invalid_iterator/index.md) for exceptions indicating errors with iterators
- [`type_error`](https://json.nlohmann.me/api/basic_json/type_error/index.md) for exceptions indicating executing a member function with a wrong type
- [`out_of_range`](https://json.nlohmann.me/api/basic_json/out_of_range/index.md) for exceptions indicating access out of the defined range
- [`other_error`](https://json.nlohmann.me/api/basic_json/other_error/index.md) for exceptions indicating other library errors

## Version history

- Since version 3.0.0.
