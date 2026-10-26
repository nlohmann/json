# Working Without Exceptions

By default, the library reports errors by throwing exceptions (see [Exceptions](../home/exceptions.md)). This page
collects what to use when exceptions are unwanted or unavailable, for example in embedded systems, game engines, or
code compiled with `-fno-exceptions`.

## Two different questions

1. **Can my code avoid *catching* exceptions?** Yes. For parsing and for accessing values there are functions that
   report failure through a return value. They work in a normal build and need no `#!cpp try`/`#!cpp catch`.
2. **Can the library be *compiled* without exceptions?** Yes, with `-fno-exceptions` or by defining
   [`JSON_NOEXCEPTION`](../api/macros/json_noexception.md). Both have the same effect: every `#!cpp throw` in the
   library becomes a call to `std::abort()`. The functions listed below never reach a `#!cpp throw` for the failures
   they report, so they keep working in this configuration. Anything else that fails aborts the program.

## Parsing

| function                                                                                    | on invalid input                                    |
|---------------------------------------------------------------------------------------------|-----------------------------------------------------|
| `#!cpp json::parse(input, nullptr, false)`                                                  | returns a *discarded* value; test with `is_discarded()` |
| [`accept`](../api/basic_json/accept.md)                                                     | returns `#!cpp false`                               |
| `#!cpp json::from_cbor(input, true, false)` (and the other `from_*` functions)              | returns a *discarded* value                         |
| [`sax_parse`](../api/basic_json/sax_parse.md) with your own handler                         | returns `#!cpp false` after calling `parse_error`   |

??? example "Example: parse and validate without exceptions"

    ```cpp
    #include <cstdint>
    #include <iostream>
    #include <vector>
    #include <nlohmann/json.hpp>
    
    using json = nlohmann::json;
    
    // None of the calls below throws, so this example also works with -fno-exceptions.
    int main()
    {
        const std::string invalid = R"({"name": "Mary", "age": )";
    
        // parse() with allow_exceptions = false returns a discarded value
        json j = json::parse(invalid, nullptr, false);
        std::cout << std::boolalpha << "parse: discarded = " << j.is_discarded() << '\n';
    
        // accept() only tells whether the input is valid JSON
        std::cout << "accept: " << json::accept(invalid) << '\n';
    
        // the binary formats have the same parameter
        const std::vector<std::uint8_t> truncated_cbor = {0x83, 0x01};
        json c = json::from_cbor(truncated_cbor, true, false);
        std::cout << "from_cbor: discarded = " << c.is_discarded() << '\n';
    
        // valid input is parsed as usual
        json valid = json::parse(R"({"name": "Mary"})", nullptr, false);
        std::cout << "valid input: " << valid << '\n';
    }
    
    ```

    Output:

    ```
    parse: discarded = true
    accept: false
    from_cbor: discarded = true
    valid input: {"name":"Mary"}
    
    ```

None of the calls in this example throws, so it also compiles and runs with `-fno-exceptions`.

The discarded value carries no message. If you need the position or the reason, use the SAX interface; see
[Parsing and exceptions](parsing/parse_exceptions.md).

## Accessing values

The access functions are not equally safe. Only some of them never throw:

| expression                          | if the key is missing or the type is wrong                                    |
|-------------------------------------|-------------------------------------------------------------------------------|
| `#!cpp j.contains("k")`             | returns `#!cpp false` for a missing key; never throws                         |
| `#!cpp j.find("k")`                 | returns `end()` for a missing key; never throws                               |
| `#!cpp j.is_string()`, ...          | the `is_*` functions test the type; never throw                               |
| `#!cpp j.get_ptr<const std::string*>()` | returns `#!cpp nullptr` for a different type; never throws                |
| `#!cpp j.at("k")`                   | throws `out_of_range.403` for a missing key                                   |
| `#!cpp j.get<int>()`                | throws `type_error.302` for a value that is not a number                      |
| `#!cpp j.value("k", 0)`             | returns the default for a missing key, but **throws `type_error.302` if `k` exists with another type** |
| `#!cpp j["k"]` (non-const)          | inserts `null` for a missing key                                              |
| `#!cpp j["k"]` (const)              | undefined behavior for a missing key                                          |

So reading a value that may be absent or of the wrong type without exceptions takes two steps: look up, then test the
type.

??? example "Example: look up a key and test its type"

    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using json = nlohmann::json;
    
    int main()
    {
        json j = json::parse(R"({"name": "Mary", "age": 42})");
    
        // look up the key, then test the type: neither step throws
        const auto keys = {"name", "age", "city"};
        for (const char* key : keys)
        {
            const auto it = j.find(key);
            if (it == j.end())
            {
                std::cout << key << ": missing\n";
            }
            else if (it->is_string())
            {
                std::cout << key << ": string \"" << it->get_ref<const std::string&>() << "\"\n";
            }
            else
            {
                std::cout << key << ": not a string, but " << it->type_name() << '\n';
            }
        }
    
        // get_ptr returns a null pointer if the value has another type
        const std::string* name = j["name"].get_ptr<const std::string*>();
        const std::string* age = j["age"].get_ptr<const std::string*>();
        std::cout << "get_ptr<string*>: name = " << (name != nullptr) << ", age = " << (age != nullptr) << '\n';
    
        // value() is NOT exception-free: it throws if the key exists with a different type
        try
        {
            std::cout << j.value("name", 0) << '\n';
        }
        catch (const json::type_error& e)
        {
            std::cout << e.what() << '\n';
        }
    }
    
    ```

    Output:

    ```
    name: string "Mary"
    age: not a string, but number
    city: missing
    get_ptr<string*>: name = 1, age = 0
    [json.exception.type_error.302] type must be number, but is string
    
    ```

The last lines of the example show why `value` is not on the safe list: it returns the default only for a *missing*
key.

For numbers, test with `is_number()` (or `is_number_integer()`, `is_number_unsigned()`, `is_number_float()`) before
calling `get<int>()`, and see [number handling](types/number_handling.md) for range and precision. Whether a value
fits into the target type is not checked by `get`.

## Converting to your own types

`from_json` functions (including the ones generated by the
[`NLOHMANN_DEFINE_TYPE_*` macros](arbitrary_types.md#simplify-your-life-with-macros)) report problems by throwing.
There is no variant that returns an error code. Without exceptions you have two options:

- Validate the JSON value yourself, as shown above, and fill your struct field by field.
- Convert in a function that is compiled **with** exceptions enabled and catches them at the boundary, returning
  `std::optional` or an error code to the rest of your code:

??? example "Example: convert to a struct and report failure as std::optional"

    ```cpp
    #include <iostream>
    #include <optional>
    #include <string>
    #include <nlohmann/json.hpp>
    
    using json = nlohmann::json;
    
    struct person
    {
        std::string name;
        int age;
    };
    
    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(person, name, age)
    
    // Compile this function with exceptions enabled and call it from code that does not use them.
    std::optional<person> to_person(const json& j)
    {
        try
        {
            return j.get<person>();
        }
        catch (const json::exception&)
        {
            return std::nullopt;
        }
    }
    
    int main()
    {
        const json good = {{"name", "Mary"}, {"age", 42}};
        const json bad = {{"name", "Mary"}, {"age", "forty-two"}};
        const json incomplete = {{"name", "Mary"}};
    
        const auto inputs = {good, bad, incomplete};
    
        for (const json& j : inputs)
        {
            if (const auto p = to_person(j))
            {
                std::cout << "person: " << p->name << ", " << p->age << '\n';
            }
            else
            {
                std::cout << "not a person: " << j << '\n';
            }
        }
    }
    
    ```

    Output:

    ```
    person: Mary, 42
    not a person: {"age":"forty-two","name":"Mary"}
    not a person: {"name":"Mary"}
    
    ```

## Overriding what happens instead of an exception

With exceptions off, you can replace the `abort()` by your own code, for example to log the message first. See
[Switch off exceptions](../home/exceptions.md#switch-off-exceptions) and
[`JSON_THROW_USER`](../api/macros/json_throw_user.md). The handler must not return normally.

## See also

- [Exceptions](../home/exceptions.md) - all exceptions and their ids
- [Parsing and exceptions](parsing/parse_exceptions.md) - the parsing alternatives in detail
- [Parsing untrusted input](parsing/untrusted_input.md)
- [`JSON_NOEXCEPTION`](../api/macros/json_noexception.md)
