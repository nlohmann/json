# SAX Interface

The library uses a SAX-like interface with the following functions:

```plantuml
interface json::sax_t {
    + {abstract} bool null()

    + {abstract} bool boolean(bool val)

    + {abstract} bool number_integer(number_integer_t val)
    + {abstract} bool number_unsigned(number_unsigned_t val)

    + {abstract} bool number_float(number_float_t val, const string_t& s)

    + {abstract} bool string(string_t& val)
    + {abstract} bool binary(binary_t& val)

    + {abstract} bool start_object(std::size_t elements)
    + {abstract} bool end_object()
    + {abstract} bool start_array(std::size_t elements)
    + {abstract} bool end_array()
    + {abstract} bool key(string_t& val)

    + {abstract} bool parse_error(std::size_t position, const std::string& last_token, const json::exception& ex)
}
```

```cpp
// called when null is parsed
bool null();

// called when a boolean is parsed; value is passed
bool boolean(bool val);

// called when a signed or unsigned integer number is parsed; value is passed
bool number_integer(number_integer_t val);
bool number_unsigned(number_unsigned_t val);

// called when a floating-point number is parsed; value and original string is passed
bool number_float(number_float_t val, const string_t& s);

// called when a string is parsed; value is passed and can be safely moved away
bool string(string_t& val);
// called when a binary value is parsed; value is passed and can be safely moved away
bool binary(binary& val);

// called when an object or array begins or ends, resp. The number of elements is passed (or -1 if not known)
bool start_object(std::size_t elements);
bool end_object();
bool start_array(std::size_t elements);
bool end_array();
// called when an object key is parsed; value is passed and can be safely moved away
bool key(string_t& val);

// called when a parse error occurs; byte position, the last token, and an exception is passed
bool parse_error(std::size_t position, const std::string& last_token, const json::exception& ex);
```

The return value of each function determines whether parsing should proceed.

To implement your own SAX handler, proceed as follows:

1. Implement the SAX interface in a class. You can use class `nlohmann::json_sax<json>` as base class, but you can also use any class where the functions described above are implemented and public.
2. Create an object of your SAX interface class, e.g. `my_sax`.
3. Call `#!cpp bool json::sax_parse(input, &my_sax);` where the first parameter can be any input like a string or an input stream and the second parameter is a pointer to your SAX interface.

Note the `sax_parse` function only returns a `#!cpp bool` indicating the result of the last executed SAX event. It does not return `json` value - it is up to you to decide what to do with the SAX events. Furthermore, no exceptions are thrown in case of a parse error - it is up to you what to do with the exception object passed to your `parse_error` implementation. Internally, the SAX interface is used for the DOM parser (class `json_sax_dom_parser`) as well as the acceptor (`json_sax_acceptor`), see file `json_sax.hpp`.

## Element position information

The position of a parsed element can be retrieved by implementing the optional methods [next_token_start](../../api/json_sax/next_token_start.md) and [next_token_end](../../api/json_sax/next_token_end.md).
These methods will be called with the parser position before any of the other methods are called and can be used to retrieve the half open bounds (`[start, end)`) of a parsed element.

These Methods come in two flavors:

1. 
```cpp
void next_token_start(std::size_t pos);
void next_token_end(std::size_t pos);
```
This flavor is called with the byte positions of each element and are available for any `nlohmann::json::input_format_t` passed to `nlohmann::json::sax_parse`.

2. 
```cpp
void next_token_start(const nlohmann::position_t& p);
void next_token_end(const nlohmann::position_t& p);
```
This flavor is called with the [detailed parser position information](../../api/position_t/index.md) of each element and are only available if `nlohmann::json::sax_parse` is called with `nlohmann::json::input_format_t::json`.
Furthermore this flavor takes precedence over the first flavor.

Depending on the required information it is possible for the SAX parser to implement all four or only one or none of these methods.

## See also

- [json_sax](../../api/json_sax/index.md) - documentation of the SAX interface
- [sax_parse](../../api/basic_json/sax_parse.md) - SAX parser
