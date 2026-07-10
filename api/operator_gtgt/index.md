# nlohmann::operator>>(basic_json)

```
std::istream& operator>>(std::istream& i, basic_json& j);
```

Deserializes an input stream to a JSON value.

## Parameters

`i` (in, out) : input stream to read a serialized JSON value from

`j` (in, out) : JSON value to write the deserialized input to

## Return value

the stream `i`

## Exceptions

- Throws [`parse_error.101`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error101) in case of an unexpected token.

## Complexity

Linear in the length of the input. The parser is a predictive LL(1) parser.

## Notes

A UTF-8 byte order mark is silently ignored.

Invalid Unicode escapes and unpaired surrogates in the input are reported as [`parse_error.101`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error101) with a detailed message.

`operator>>` parses exactly one JSON value and leaves the stream positioned right after it, so it can be called repeatedly to read a sequence of concatenated JSON values from the same stream:

```
json j1, j2;
input >> j1;  // parses the first value, stream now positioned right after it
input >> j2;  // parses the next value
```

Note this does **not** work for [JSON Lines](https://json.nlohmann.me/features/parsing/json_lines/index.md) (newline-delimited JSON) input -- see that page for why and for the recommended alternative.

Deprecation

This function replaces function `std::istream& operator<<(basic_json& j, std::istream& i)` which has been deprecated in version 3.0.0. It will be removed in version 4.0.0. Please replace calls like `j << i;` with `i >> j;`.

## Examples

Example

The example below shows how a JSON value is constructed by reading a serialization from a stream.

```
#include <iostream>
#include <iomanip>
#include <sstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create stream with serialized JSON
    std::stringstream ss;
    ss << R"({
        "number": 23,
        "string": "Hello, world!",
        "array": [1, 2, 3, 4, 5],
        "boolean": false,
        "null": null
    })";

    // create JSON value and read the serialization from the stream
    json j;
    ss >> j;

    // serialize JSON
    std::cout << std::setw(2) << j << '\n';
}
```

Output:

```
{
  "array": [
    1,
    2,
    3,
    4,
    5
  ],
  "boolean": false,
  "null": null,
  "number": 23,
  "string": "Hello, world!"
}
```

## See also

- [accept](https://json.nlohmann.me/api/basic_json/accept/index.md) - check if the input is valid JSON
- [parse](https://json.nlohmann.me/api/basic_json/parse/index.md) - deserialize from a compatible input

## Version history

- Added in version 1.0.0.
