# Parsing

This library can create a JSON value from a wide range of inputs. This page gives an overview of the available parsing
functions and how they behave; the linked pages go into more detail.

## Input

The [`parse`](../../api/basic_json/parse.md) function reads a JSON value from an input. The input can be

- a string (`#!cpp std::string`, C string, or string literal),
- a `#!cpp std::istream` (e.g., an `#!cpp std::ifstream` reading from a file),
- a `#!cpp FILE*` pointer,
- a pair of iterators over a contiguous range (e.g., a `#!cpp std::vector<std::uint8_t>`), or
- a contiguous container.

```cpp
// parse from a string
json j = json::parse(R"({"happy": true, "pi": 3.141})");

// parse from a file
std::ifstream f("example.json");
json data = json::parse(f);
```

The input must be encoded in UTF-8; other encodings are not supported. A single input may contain only one JSON value.
Inputs consisting of multiple values separated by newlines are handled by the [JSON Lines](json_lines.md) format.

By default, the library rejects comments and trailing commas. Both can be enabled with parameters of the `parse`
function — see [comments](../comments.md) and [trailing commas](../trailing_commas.md).

## SAX vs. DOM parsing

The library offers two parsing models:

- **DOM parsing** (the default): the complete input is read and stored as an in-memory `basic_json` value that can be
  traversed and modified freely. This is what [`parse`](../../api/basic_json/parse.md) does, and it is the right choice
  for most use cases.
- **SAX parsing**: instead of building a value, the parser reports events (such as "a string was read" or "an object
  started") to a handler that you implement. This avoids building the full value in memory and is useful for very large
  inputs or when you only need to extract parts of the input. See the [SAX interface](sax_interface.md) for details and
  [`sax_parse`](../../api/basic_json/sax_parse.md) for the API.

You can influence a DOM parse without switching to the SAX interface by passing a
[parser callback](parser_callbacks.md), which is called during parsing and can, for example, discard parts of the input.

## Exceptions

When the input is not valid JSON, the `parse` function throws an exception by default. If exceptions are undesired or
unavailable, the parser can instead return a discarded value, or [`accept`](../../api/basic_json/accept.md) can be used
to only check whether an input is valid JSON. See [parsing and exceptions](parse_exceptions.md) for the available
options.

## See also

- [`parse`](../../api/basic_json/parse.md) - deserialize from a compatible input
- [`accept`](../../api/basic_json/accept.md) - check if the input is valid JSON
- [`sax_parse`](../../api/basic_json/sax_parse.md) - generate SAX events
- [JSON Lines](json_lines.md) - parse newline-delimited JSON
- [parser callbacks](parser_callbacks.md) - influence the parsing by a callback function
- [SAX interface](sax_interface.md) - implement a custom SAX handler
- [parsing and exceptions](parse_exceptions.md) - control error handling
