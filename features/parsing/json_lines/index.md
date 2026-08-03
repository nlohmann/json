# JSON Lines

The [JSON Lines](https://jsonlines.org) format is a text format of newline-delimited JSON. In particular:

1. The input must be UTF-8 encoded.
1. Every line must be a valid JSON value.
1. The line separator must be `\n`. As `\r` is silently ignored, `\r\n` is also supported.
1. The final character may be `\n`, but is not required to be one.

JSON Text example

```
{"name": "Gilbert", "wins": [["straight", "7♣"], ["one pair", "10♥"]]}
{"name": "Alexa", "wins": [["two pair", "4♠"], ["two pair", "9♠"]]}
{"name": "May", "wins": []}
{"name": "Deloise", "wins": [["three of a kind", "5♣"]]}
```

JSON Lines input with more than one value is treated as invalid JSON by the [`parse`](https://json.nlohmann.me/api/basic_json/parse/index.md) or [`accept`](https://json.nlohmann.me/api/basic_json/accept/index.md) functions. To process it line by line, functions like [`std::getline`](https://en.cppreference.com/w/cpp/string/basic_string/getline) can be used:

Example: Parse JSON Text input line by line

The example below demonstrates how JSON Lines can be processed.

```
#include <sstream>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // JSON Lines (see https://jsonlines.org)
    std::stringstream input;
    input << R"({"name": "Gilbert", "wins": [["straight", "7♣"], ["one pair", "10♥"]]}
{"name": "Alexa", "wins": [["two pair", "4♠"], ["two pair", "9♠"]]}
{"name": "May", "wins": []}
{"name": "Deloise", "wins": [["three of a kind", "5♣"]]}
)";

    std::string line;
    while (std::getline(input, line))
    {
        std::cout << json::parse(line) << std::endl;
    }
}
```

Output:

```
{"name":"Gilbert","wins":[["straight","7♣"],["one pair","10♥"]]}
{"name":"Alexa","wins":[["two pair","4♠"],["two pair","9♠"]]}
{"name":"May","wins":[]}
{"name":"Deloise","wins":[["three of a kind","5♣"]]}
```

Note

Using [`operator>>`](https://json.nlohmann.me/api/operator_gtgt/index.md) like

```
json j;
while (input >> j)
{
    std::cout << j << std::endl;
}
```

with a JSON Lines input does not work, because the parser will try to parse one value after the last one.

This is different from parsing a stream of *concatenated* (non-newline-delimited) JSON values, for which `operator>>` does work, provided that a value that is a number is followed by whitespace -- see its [notes](https://json.nlohmann.me/api/operator_gtgt/#notes) for details.
