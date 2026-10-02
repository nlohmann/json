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

The return value indicates whether the parsing should continue, so the function should usually return `#!cpp false`.

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
