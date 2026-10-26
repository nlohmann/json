# Parsing and Exceptions

When the input is not valid JSON, an exception of type [`parse_error`](https://json.nlohmann.me/home/exceptions/#parse-errors) is thrown. This exception contains the position in the input where the error occurred, together with a diagnostic message and the last read input token. The exceptions page contains a [list of examples for parse error exceptions](https://json.nlohmann.me/home/exceptions/#parse-errors). In case you process untrusted input, always enclose your code with a `try`/`catch` block, like

```
json j;
try
{
    j = json::parse(my_input);
}
catch (json::parse_error& ex)
{
    std::cerr << "parse error at byte " << ex.byte << std::endl;
}
```

In case exceptions are undesired or not supported by the environment, there are different ways to proceed:

Tip

[Working without exceptions](https://json.nlohmann.me/features/no_exceptions/index.md) also covers accessing values and converting to your own types.

## Switch off exceptions

The [`parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md) function accepts a `bool` parameter `allow_exceptions` which controls whether an exception is thrown when a parse error occurs (`true`, default) or whether a discarded value should be returned (`false`).

```
json j = json::parse(my_input, nullptr, false);
if (j.is_discarded())
{
    std::cerr << "parse error" << std::endl;
}
```

Note there is no diagnostic information available in this scenario.

## Use accept() function

Alternatively, function [`accept()`](https://json.nlohmann.me/api/basic_json/accept/index.md) can be used which does not return a `json` value, but a `bool` indicating whether the input is valid JSON.

```
if (!json::accept(my_input))
{
    std::cerr << "parse error" << std::endl;
}
```

Again, there is no diagnostic information available.

## User-defined SAX interface

Finally, you can implement the [SAX interface](https://json.nlohmann.me/features/parsing/sax_interface/index.md) and decide what should happen in case of a parse error.

This function has the following interface:

```
bool parse_error(std::size_t position,
                 const std::string& last_token,
                 const json::exception& ex);
```

The return value indicates whether the parsing should continue, so the function should usually return `false`.

Example: report parse errors without exceptions

The example derives from the library's DOM parser and overrides `parse_error` to print the error instead of throwing. Note the DOM parser is an implementation detail (`nlohmann::detail`) and may change between releases; see [Do not use the `detail` namespace](https://json.nlohmann.me/integration/migration_guide/#do-not-use-the-detail-namespace).

```
#include <iostream>
#include <nlohmann/json.hpp>

using nlohmann::json;

// a DOM parser that reports parse errors instead of throwing
class sax_no_exception : public nlohmann::detail::json_sax_dom_parser<json, nlohmann::detail::string_input_adapter_type>
{
  public:
    explicit sax_no_exception(json& j)
        : nlohmann::detail::json_sax_dom_parser<json, nlohmann::detail::string_input_adapter_type>(j, false)
    {}

    bool parse_error(std::size_t position,
                     const std::string& last_token,
                     const json::exception& ex)
    {
        std::cout << "parse error at input byte " << position << "\n"
                  << ex.what() << "\n"
                  << "last read: \"" << last_token << "\""
                  << '\n';
        return false;
    }
};

int main()
{
    std::string myinput = "[1,2,3,]";

    json result;
    sax_no_exception sax(result);

    bool parse_result = json::sax_parse(myinput, &sax);
    if (!parse_result)
    {
        std::cout << "parsing unsuccessful!" << '\n';
    }

    std::cout << "parsed value: " << result << '\n';
}
```

Output:

```
parse error at input byte 8
[json.exception.parse_error.101] parse error at line 1, column 8: syntax error while parsing value - unexpected ']'; expected '[', '{', or a literal
last read: "3,]"
parsing unsuccessful!
parsed value: [1,2,3]
```

## Where did the error occur?

The message of a [`parse_error`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error101) for JSON text contains the line and column of the error:

```
[json.exception.parse_error.101] parse error at line 3, column 8: syntax error while parsing value - unexpected ']'; expected '[', '{', or a literal
```

The exception object itself only stores the **byte index** of the last read character in the member `byte` (the first byte of the input has index 1). The same index is passed to `parse_error` in the [SAX interface](https://json.nlohmann.me/features/parsing/sax_interface/index.md). If you need the line and column as numbers, for example to show them in an editor, compute them from the input:

Example: compute line and column of a parse error

```
#include <iostream>
#include <utility>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// line and column (both starting at 1) of a byte index in a text
std::pair<std::size_t, std::size_t> line_column(const std::string& input, std::size_t byte)
{
    std::size_t line = 1;
    std::size_t column = 1;
    for (std::size_t i = 0; i + 1 < byte && i < input.size(); ++i)
    {
        if (input[i] == '\n')
        {
            ++line;
            column = 1;
        }
        else
        {
            ++column;
        }
    }
    return {line, column};
}

int main()
{
    const std::string input = "{\n  \"a\": 1,\n  \"b\": ]\n}";

    try
    {
        const json j = json::parse(input);
        std::cout << j << '\n';
    }
    catch (const json::parse_error& e)
    {
        const auto position = line_column(input, e.byte);
        std::cout << e.what() << '\n';
        std::cout << "byte " << e.byte << " = line " << position.first << ", column " << position.second << '\n';
    }
}
```

Output:

```
[json.exception.parse_error.101] parse error at line 3, column 8: syntax error while parsing value - unexpected ']'; expected '[', '{', or a literal
byte 20 = line 3, column 8
```

Columns count bytes, so a line with multi-byte UTF-8 characters before the error may differ from the column your editor shows.

### Where is the value that caused a later error?

A `parse_error` is raised while the text is read. Many mistakes show up later: the text is valid JSON, but a value has the wrong type when you convert it (`type_error.302`), or a key is missing (`out_of_range.403`). The exception then says what is wrong, but not where in the input the value was. Define [`JSON_DIAGNOSTIC_POSITIONS`](https://json.nlohmann.me/api/macros/json_diagnostic_positions/index.md) before including the library to add the byte range of the offending value to such messages (since version 3.12.0), and to query the range of any value with [`start_pos()`](https://json.nlohmann.me/api/basic_json/start_pos/index.md) and [`end_pos()`](https://json.nlohmann.me/api/basic_json/end_pos/index.md):

Example: locate a value with diagnostic positions

```
#define JSON_DIAGNOSTIC_POSITIONS 1
#include <iostream>
#include <utility>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// line and column (both starting at 1) of a byte index in a text
std::pair<std::size_t, std::size_t> line_column(const std::string& input, std::size_t byte)
{
    std::size_t line = 1;
    std::size_t column = 1;
    for (std::size_t i = 0; i + 1 < byte && i < input.size(); ++i)
    {
        if (input[i] == '\n')
        {
            ++line;
            column = 1;
        }
        else
        {
            ++column;
        }
    }
    return {line, column};
}

int main()
{
    const std::string input = "{\n  \"name\": \"Mary\",\n  \"age\": \"forty-two\"\n}";
    const json j = json::parse(input); // the input is valid JSON ...

    try
    {
        const int age = j["age"]; // ... but the value has the wrong type
        std::cout << age << '\n';
    }
    catch (const json::exception& e)
    {
        std::cout << e.what() << '\n';

        // start_pos() is a 0-based index into the input; the helper expects a 1-based byte index
        const auto position = line_column(input, j["age"].start_pos() + 1);
        std::cout << "the value starts at line " << position.first << ", column " << position.second << '\n';
    }
}
```

Output:

```
[json.exception.type_error.302] (bytes 29-40) type must be number, but is string
the value starts at line 3, column 10
```

Positions are only available for values created by [`parse`](https://json.nlohmann.me/api/basic_json/parse/index.md), they are not updated when a value is changed, and the macro makes every value 16 bytes larger on 64-bit platforms, so use it where the cost is acceptable, for example for configuration files. Note that `start_pos()` is a 0-based index into the input, whereas `byte` of a `parse_error` starts at 1.

For binary formats such as CBOR, there are no lines; `byte` is the position in the byte sequence. To find out how many bytes a successfully parsed value used, see [Several values in one stream](https://json.nlohmann.me/features/parsing/large_and_partial_input/#several-values-in-one-stream).
