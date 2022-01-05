# JSON Lines

The [JSON Lines](https://jsonlines.org) format is a text format of newline-delimited JSON. In particular:

1. The input must be UTF-8 encoded.
2. Every line must be a valid JSON value.
3. The line separator must be `\n`. As `\r` is silently ignored, `\r\n` is also supported.
4. The final character may be `\n`, but is not required to be one.

!!! example "JSON Text example"

    ```json
    {"name": "Gilbert", "wins": [["straight", "7♣"], ["one pair", "10♥"]]}
    {"name": "Alexa", "wins": [["two pair", "4♠"], ["two pair", "9♠"]]}
    {"name": "May", "wins": []}
    {"name": "Deloise", "wins": [["three of a kind", "5♣"]]}
    ```

JSON Lines input with more than one value is treated as invalid JSON by the [`parse`](../../api/basic_json/parse.md) or
[`accept`](../../api/basic_json/accept.md) functions. To process it line by line, functions like
[`std::getline`](https://en.cppreference.com/w/cpp/string/basic_string/getline) can be used:

!!! example "Example: Parse JSON Text input line by line"

    The example below demonstrates how JSON Lines can be processed.

    ```cpp
    --8<-- "examples/json_lines.cpp"
    ```
    
    Output:

    ```json
    --8<-- "examples/json_lines.output"
    ```

!!! warning "Note"

    Using [`operator>>`](../../api/basic_json/operator_gtgt.md) like
    
    ```cpp
    json j;
    while (input >> j)
    {
        std::cout << j << std::endl;
    }
    ```
    
    with a JSON Lines input does not work, because the parser will try to parse one value after the last one.
