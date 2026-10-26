# Parsing and Exceptions

When the input is not valid JSON, an exception of type [`parse_error`](../../home/exceptions.md#parse-errors) is thrown.
This exception contains the position in the input where the error occurred, together with a diagnostic message and the
last read input token. The exceptions page contains a
[list of examples for parse error exceptions](../../home/exceptions.md#parse-errors). In case you process untrusted
input, always enclose your code with a `#!cpp try`/`#!cpp catch` block, like

```cpp
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


!!! tip

    [Working without exceptions](../no_exceptions.md) also covers accessing values and converting to your own types.

## Switch off exceptions

The [`parse()`](../../api/basic_json/parse.md) function accepts a `#!cpp bool` parameter `allow_exceptions` which
controls whether an exception is thrown when a parse error occurs (`#!cpp true`, default) or whether a discarded value
should be returned (`#!cpp false`).

```cpp
json j = json::parse(my_input, nullptr, false);
if (j.is_discarded())
{
    std::cerr << "parse error" << std::endl;
}
```

Note there is no diagnostic information available in this scenario.

## Use accept() function

Alternatively, function [`accept()`](../../api/basic_json/accept.md) can be used which does not return a `json` value,
but a `#!cpp bool` indicating whether the input is valid JSON.

```cpp
if (!json::accept(my_input))
{
    std::cerr << "parse error" << std::endl;
}
```

Again, there is no diagnostic information available.


## User-defined SAX interface

Finally, you can implement the [SAX interface](sax_interface.md) and decide what should happen in case of a parse error.

This function has the following interface:

```cpp
bool parse_error(std::size_t position,
                 const std::string& last_token,
                 const json::exception& ex);
```

The return value decides whether to stop parsing (`#!cpp false`) or to repair the error and continue
(`#!cpp true`); see [error recovery](error_recovery.md) for the latter.

??? example "Example: report parse errors without exceptions"

    The example derives from the library's DOM parser and overrides `parse_error` to print the error instead of
    throwing. Note the DOM parser is an implementation detail (`nlohmann::detail`) and may change between releases;
    see [Do not use the `detail` namespace](../../integration/migration_guide.md#do-not-use-the-detail-namespace).

    ```cpp
    --8<-- "examples/sax_no_exception.cpp"
    ```

    Output:

    ```
    --8<-- "examples/sax_no_exception.output"
    ```

## Where did the error occur?

The message of a [`parse_error`](../../home/exceptions.md#jsonexceptionparse_error101) for JSON text contains the line
and column of the error:

```
[json.exception.parse_error.101] parse error at line 3, column 8: syntax error while parsing value - unexpected ']'; expected '[', '{', or a literal
```

The exception object itself only stores the **byte index** of the last read character in the member `byte` (the first
byte of the input has index 1). The same index is passed to `parse_error` in the [SAX interface](sax_interface.md). If
you need the line and column as numbers, for example to show them in an editor, compute them from the input:

??? example "Example: compute line and column of a parse error"

    ```cpp
    --8<-- "examples/parse_error_position.cpp"
    ```

    Output:

    ```
    --8<-- "examples/parse_error_position.output"
    ```

Columns count bytes, so a line with multi-byte UTF-8 characters before the error may differ from the column your editor
shows.

### Where is the value that caused a later error?

A `parse_error` is raised while the text is read. Many mistakes show up later: the text is valid JSON, but a value has
the wrong type when you convert it (`type_error.302`), or a key is missing (`out_of_range.403`). The exception then says
what is wrong, but not where in the input the value was. Define
[`JSON_DIAGNOSTIC_POSITIONS`](../../api/macros/json_diagnostic_positions.md) before including the library to add the
byte range of the offending value to such messages (since version 3.12.0), and to query the range of any value with
[`start_pos()`](../../api/basic_json/start_pos.md) and [`end_pos()`](../../api/basic_json/end_pos.md):

??? example "Example: locate a value with diagnostic positions"

    ```cpp
    --8<-- "examples/parse_error_position_diagnostic.cpp"
    ```

    Output:

    ```
    --8<-- "examples/parse_error_position_diagnostic.output"
    ```

Positions are only available for values created by [`parse`](../../api/basic_json/parse.md), they are not updated when a
value is changed, and the macro makes every value 16 bytes larger on 64-bit platforms, so use it where the cost is
acceptable, for example for configuration files. Note that `start_pos()` is a 0-based index into the input, whereas
`byte` of a `parse_error` starts at 1.

For binary formats such as CBOR, there are no lines; `byte` is the position in the byte sequence. To find out how many
bytes a successfully parsed value used, see
[Several values in one stream](large_and_partial_input.md#several-values-in-one-stream).
