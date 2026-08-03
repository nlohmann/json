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

`operator>>` parses exactly one JSON value, so it can be called repeatedly to read a sequence of concatenated JSON values from the same stream:

```
json j1, j2;
input >> j1;  // parses the first value
input >> j2;  // parses the next value
```

A number must be followed by whitespace

A number is only terminated by the character that follows it. That character is read from the stream to detect the end of the number, and it is **not** put back. When a value that is a number is immediately followed by the next value, the first character of that next value is lost:

```
std::istringstream input("1true");
json j1, j2;
input >> j1;  // j1 == 1
input >> j2;  // throws parse_error.101: the stream now starts at "rue"
```

Separating the values with whitespace avoids this, because the character that is eaten is then the separator:

```
std::istringstream input("1 true");
json j1, j2;
input >> j1;  // j1 == 1
input >> j2;  // j2 == true
```

Only numbers are affected. Values ending in a self-delimiting character do not read past themselves, so `truefalse`, `[1][2]`, `{"a":1}{"b":2}`, and `"a""b"` can be read back to back without a separator.

This is tracked in [#5340](https://github.com/nlohmann/json/issues/5340).

Note that reading concatenated values does **not** work for [JSON Lines](https://json.nlohmann.me/features/parsing/json_lines/index.md) (newline-delimited JSON) input -- see that page for why and for the recommended alternative.

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
