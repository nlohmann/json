# Parsing

This library can create a JSON value from a wide range of inputs. This page gives an overview of the available parsing functions and how they behave; the linked pages go into more detail.

```
flowchart LR
    I["JSON input"] --> P["parse()"]
    I --> S["sax_parse()"]
    I --> A["accept()"]
    P -->|"optional parser callback filters values"| D["basic_json value (DOM)"]
    S --> H["events delivered to a user SAX handler"]
    A --> V["bool: is the input valid JSON?"]
```

## Input

The [`parse`](https://json.nlohmann.me/api/basic_json/parse/index.md) function reads a JSON value from an input. The input can be

- a string (`std::string`, C string, or string literal),
- a `std::istream` (e.g., an `std::ifstream` reading from a file),
- a `FILE*` pointer,
- a pair of iterators over a contiguous range (e.g., a `std::vector<std::uint8_t>`), or
- a contiguous container.

```
// parse from a string
json j = json::parse(R"({"happy": true, "pi": 3.141})");

// parse from a file
std::ifstream f("example.json");
json data = json::parse(f);
```

The input must be encoded in UTF-8; other encodings are not supported. A single input may contain only one JSON value. Inputs consisting of multiple values separated by newlines are handled by the [JSON Lines](https://json.nlohmann.me/features/parsing/json_lines/index.md) format.

By default, the library rejects comments and trailing commas. Both can be enabled with parameters of the `parse` function — see [comments](https://json.nlohmann.me/features/comments/index.md) and [trailing commas](https://json.nlohmann.me/features/trailing_commas/index.md).

## Strictness and trailing data

[`parse`](https://json.nlohmann.me/api/basic_json/parse/index.md) reads a single JSON value and requires the whole input to be consumed: any non-whitespace data after the value is reported as a parse error. Use it when you want to guarantee that an input is exactly one complete JSON document.

[`operator>>`](https://json.nlohmann.me/api/operator_gtgt/index.md) follows relaxed `std::istream` semantics instead: it parses one JSON value and leaves the stream positioned right after it, without requiring the rest of the stream to be consumed. This is what makes it possible to read several concatenated values from the same stream, but it also means that "a valid document followed by trailing bytes" is accepted rather than rejected. If you are validating conformance, or need to reject any input that is not exactly one JSON document, prefer `parse`.

When using `operator>>` to read several concatenated values this way, a value that is a number must be followed by whitespace, because `operator>>` consumes the character that terminates a number, unless [`JSON_PRECISE_STREAM_POSITION`](https://json.nlohmann.me/api/macros/json_precise_stream_position/index.md) is defined to `1` — see the [`operator>>` notes](https://json.nlohmann.me/api/operator_gtgt/#notes) for details and examples.

## Input sources and performance

All inputs produce the same values and the same exceptions, but they are read in different ways, which makes some of them faster than others:

| input                                                                                                            | how it is read                                                                                                                      |
| ---------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| strings, string views, string literals, contiguous containers, pointer or iterator ranges over contiguous memory | the whole input is scanned in bulk: runs of string characters, numbers, and indentation are recognized several bytes at a time      |
| `std::istream` (`std::ifstream`, `std::istringstream`, ...)                                                      | the characters the stream buffer holds are scanned in bulk like a string; the stream buffer is asked for more when they are used up |
| `FILE*`                                                                                                          | one character at a time, with the file locked once for the whole parse                                                              |
| other iterator ranges (e.g., `std::list<char>`, `std::istreambuf_iterator<char>`), wide strings                  | one character at a time                                                                                                             |

Parsing a file from a `std::ifstream` is therefore only about 10 to 20 % slower than reading the whole file into a `std::string` first and parsing that, and it needs no memory for a copy of the file. The stream is never read ahead: after parsing, it is positioned exactly as if every character had been read one at a time, so [`operator>>`](https://json.nlohmann.me/api/operator_gtgt/index.md) can still read several values from one stream (see also [JSON Lines](https://json.nlohmann.me/features/parsing/json_lines/index.md)).

Two macros switch these optimizations off without changing any result: [`JSON_DISABLE_STREAM_BULK_SCAN`](https://json.nlohmann.me/api/macros/json_disable_stream_bulk_scan/index.md) for stream buffers that do not follow the usual `std::streambuf` contract, and [`JSON_DISABLE_UNLOCKED_FILE_IO`](https://json.nlohmann.me/api/macros/json_disable_unlocked_file_io/index.md) for programs in which another thread must use the same `FILE` object while it is parsed.

## SAX vs. DOM parsing

The library offers two parsing models:

- **DOM parsing** (the default): the complete input is read and stored as an in-memory `basic_json` value that can be traversed and modified freely. This is what [`parse`](https://json.nlohmann.me/api/basic_json/parse/index.md) does, and it is the right choice for most use cases.
- **SAX parsing**: instead of building a value, the parser reports events (such as "a string was read" or "an object started") to a handler that you implement. This avoids building the full value in memory and is useful for very large inputs or when you only need to extract parts of the input. See the [SAX interface](https://json.nlohmann.me/features/parsing/sax_interface/index.md) for details and [`sax_parse`](https://json.nlohmann.me/api/basic_json/sax_parse/index.md) for the API.

You can influence a DOM parse without switching to the SAX interface by passing a [parser callback](https://json.nlohmann.me/features/parsing/parser_callbacks/index.md), which is called during parsing and can, for example, discard parts of the input.

## Exceptions

When the input is not valid JSON, the `parse` function throws an exception by default. If exceptions are undesired or unavailable, the parser can instead return a discarded value, or [`accept`](https://json.nlohmann.me/api/basic_json/accept/index.md) can be used to only check whether an input is valid JSON. See [parsing and exceptions](https://json.nlohmann.me/features/parsing/parse_exceptions/index.md) for the available options.

## See also

- [`parse`](https://json.nlohmann.me/api/basic_json/parse/index.md) - deserialize from a compatible input
- [`accept`](https://json.nlohmann.me/api/basic_json/accept/index.md) - check if the input is valid JSON
- [`sax_parse`](https://json.nlohmann.me/api/basic_json/sax_parse/index.md) - generate SAX events
- [JSON Lines](https://json.nlohmann.me/features/parsing/json_lines/index.md) - parse newline-delimited JSON
- [parser callbacks](https://json.nlohmann.me/features/parsing/parser_callbacks/index.md) - influence the parsing by a callback function
- [SAX interface](https://json.nlohmann.me/features/parsing/sax_interface/index.md) - implement a custom SAX handler
- [parsing and exceptions](https://json.nlohmann.me/features/parsing/parse_exceptions/index.md) - control error handling
- [parsing untrusted input](https://json.nlohmann.me/features/parsing/untrusted_input/index.md) - what to consider when parsing input from untrusted sources
