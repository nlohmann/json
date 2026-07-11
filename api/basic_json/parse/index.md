# nlohmann::basic_json::parse

```
// (1)
template<typename InputType>
static basic_json parse(InputType&& i,
                        const parser_callback_t cb = nullptr,
                        const bool allow_exceptions = true,
                        const bool ignore_comments = false,
                        const bool ignore_trailing_commas = false);

// (2)
template<typename IteratorType, typename SentinelType = IteratorType>
static basic_json parse(IteratorType first, SentinelType last,
                        const parser_callback_t cb = nullptr,
                        const bool allow_exceptions = true,
                        const bool ignore_comments = false,
                        const bool ignore_trailing_commas = false);
```

1. Deserialize from a compatible input.

1. Deserialize from a pair of character iterators, or an iterator and a sentinel of a different type (C++20 ranges support)

   The `value_type` of the iterator must be an integral type with size of 1, 2, or 4 bytes, which will be interpreted respectively as UTF-8, UTF-16, and UTF-32. If `SentinelType` differs from `IteratorType`, it must be comparable to the iterator type with `operator!=`.

## Template parameters

`InputType` : A compatible input, for instance:

```
- an `std::istream` object
- a `FILE` pointer (throws if null)
- a C-style array of characters
- a pointer to a null-terminated string of single byte characters (throws if null)
- a `std::string`
- a container `obj` for which `begin(obj)` and `end(obj)` produce a valid pair of iterators
  (as found via ADL or member functions, with semantics compatible to `std::begin` and `std::end`)
```

`IteratorType` : a compatible iterator type, for instance.

```
- a pair of `std::string::iterator` or `std::vector<std::uint8_t>::iterator`
- a pair of pointers such as `ptr` and `ptr + len`
```

`SentinelType` : defaults to `IteratorType`; may be a different type comparable to `IteratorType` via `operator!=`, for instance.

```
- a custom sentinel type for C++20 ranges
- `std::counted_iterator` with a different sentinel type
```

## Parameters

`i` (in) : Input to parse from.

`cb` (in) : a parser callback function of type [`parser_callback_t`](https://json.nlohmann.me/api/basic_json/parser_callback_t/index.md) which is used to control the deserialization by filtering unwanted values (optional)

`allow_exceptions` (in) : whether to throw exceptions in case of a parse error (optional, `true` by default)

`ignore_comments` (in) : whether comments should be ignored and treated like whitespace (`true`) or yield a parse error (`false`); (optional, `false` by default)

`ignore_trailing_commas` (in) : whether trailing commas in arrays or objects should be ignored and treated like whitespace (`true`) or yield a parse error (`false`); (optional, `false` by default)

`first` (in) : iterator to the start of a character range

`last` (in) : iterator to the end of a character range, or a sentinel value that compares equal to the end iterator with `operator!=`

## Return value

Deserialized JSON value; in case of a parse error and `allow_exceptions` set to `false`, the return value will be `value_t::discarded`. The latter can be checked with [`is_discarded`](https://json.nlohmann.me/api/basic_json/is_discarded/index.md).

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

- Throws [`parse_error.101`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error101) in case of an unexpected token, or empty input like a null `FILE*` or `char*` pointer.

## Complexity

Linear in the length of the input. The parser is a predictive LL(1) parser. The complexity can be higher if the parser callback function `cb` or reading from (1) the input `i` or (2) the iterator range \[`first`, `last`\] has a super-linear complexity.

## Notes

A UTF-8 byte order mark is silently ignored.

Invalid Unicode escapes and unpaired surrogates in the input are reported as [`parse_error.101`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error101) with a detailed message.

## Examples

Parsing from a character array

The example below demonstrates the `parse()` function reading from an array.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // a JSON text
    char text[] = R"(
    {
        "Image": {
            "Width":  800,
            "Height": 600,
            "Title":  "View from 15th Floor",
            "Thumbnail": {
                "Url":    "http://www.example.com/image/481989943",
                "Height": 125,
                "Width":  100
            },
            "Animated" : false,
            "IDs": [116, 943, 234, 38793]
        }
    }
    )";

    // parse and serialize JSON
    json j_complete = json::parse(text);
    std::cout << std::setw(4) << j_complete << "\n\n";
}
```

Output:

```
{
    "Image": {
        "Animated": false,
        "Height": 600,
        "IDs": [
            116,
            943,
            234,
            38793
        ],
        "Thumbnail": {
            "Height": 125,
            "Url": "http://www.example.com/image/481989943",
            "Width": 100
        },
        "Title": "View from 15th Floor",
        "Width": 800
    }
}
```

Parsing from a string

The example below demonstrates the `parse()` function with and without callback function.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // a JSON text
    auto text = R"(
    {
        "Image": {
            "Width":  800,
            "Height": 600,
            "Title":  "View from 15th Floor",
            "Thumbnail": {
                "Url":    "http://www.example.com/image/481989943",
                "Height": 125,
                "Width":  100
            },
            "Animated" : false,
            "IDs": [116, 943, 234, 38793]
        }
    }
    )";

    // parse and serialize JSON
    json j_complete = json::parse(text);
    std::cout << std::setw(4) << j_complete << "\n\n";

    // define parser callback
    json::parser_callback_t cb = [](int depth, json::parse_event_t event, json & parsed)
    {
        // skip object elements with key "Thumbnail"
        if (event == json::parse_event_t::key and parsed == json("Thumbnail"))
        {
            return false;
        }
        else
        {
            return true;
        }
    };

    // parse (with callback) and serialize JSON
    json j_filtered = json::parse(text, cb);
    std::cout << std::setw(4) << j_filtered << '\n';
}
```

Output:

```
{
    "Image": {
        "Animated": false,
        "Height": 600,
        "IDs": [
            116,
            943,
            234,
            38793
        ],
        "Thumbnail": {
            "Height": 125,
            "Url": "http://www.example.com/image/481989943",
            "Width": 100
        },
        "Title": "View from 15th Floor",
        "Width": 800
    }
}

{
    "Image": {
        "Animated": false,
        "Height": 600,
        "IDs": [
            116,
            943,
            234,
            38793
        ],
        "Title": "View from 15th Floor",
        "Width": 800
    }
}
```

Parsing from an input stream

The example below demonstrates the `parse()` function with and without callback function.

```
#include <iostream>
#include <iomanip>
#include <sstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // a JSON text
    auto text = R"(
    {
        "Image": {
            "Width":  800,
            "Height": 600,
            "Title":  "View from 15th Floor",
            "Thumbnail": {
                "Url":    "http://www.example.com/image/481989943",
                "Height": 125,
                "Width":  100
            },
            "Animated" : false,
            "IDs": [116, 943, 234, 38793]
        }
    }
    )";

    // fill a stream with JSON text
    std::stringstream ss;
    ss << text;

    // parse and serialize JSON
    json j_complete = json::parse(ss);
    std::cout << std::setw(4) << j_complete << "\n\n";

    // define parser callback
    json::parser_callback_t cb = [](int depth, json::parse_event_t event, json & parsed)
    {
        // skip object elements with key "Thumbnail"
        if (event == json::parse_event_t::key and parsed == json("Thumbnail"))
        {
            return false;
        }
        else
        {
            return true;
        }
    };

    // fill a stream with JSON text
    ss.clear();
    ss << text;

    // parse (with callback) and serialize JSON
    json j_filtered = json::parse(ss, cb);
    std::cout << std::setw(4) << j_filtered << '\n';
}
```

Output:

```
{
    "Image": {
        "Animated": false,
        "Height": 600,
        "IDs": [
            116,
            943,
            234,
            38793
        ],
        "Thumbnail": {
            "Height": 125,
            "Url": "http://www.example.com/image/481989943",
            "Width": 100
        },
        "Title": "View from 15th Floor",
        "Width": 800
    }
}

{
    "Image": {
        "Animated": false,
        "Height": 600,
        "IDs": [
            116,
            943,
            234,
            38793
        ],
        "Title": "View from 15th Floor",
        "Width": 800
    }
}
```

Parsing from a contiguous container

The example below demonstrates the `parse()` function reading from a contiguous container.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // a JSON text given as std::vector
    std::vector<std::uint8_t> text = {'[', '1', ',', '2', ',', '3', ']', '\0'};

    // parse and serialize JSON
    json j_complete = json::parse(text);
    std::cout << std::setw(4) << j_complete << "\n\n";
}
```

Output:

```
[
    1,
    2,
    3
]
```

Parsing from a non-null-terminated string

The example below demonstrates the `parse()` function reading from a string that is not null-terminated.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // a JSON text given as string that is not null-terminated
    const char* ptr = "[1,2,3]another value";

    // parse and serialize JSON
    json j_complete = json::parse(ptr, ptr + 7);
    std::cout << std::setw(4) << j_complete << "\n\n";
}
```

Output:

```
[
    1,
    2,
    3
]
```

Parsing from an iterator pair

The example below demonstrates the `parse()` function reading from an iterator pair.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // a JSON text given an input with other values
    std::vector<std::uint8_t> input = {'[', '1', ',', '2', ',', '3', ']', 'o', 't', 'h', 'e', 'r'};

    // parse and serialize JSON
    json j_complete = json::parse(input.begin(), input.begin() + 7);
    std::cout << std::setw(4) << j_complete << "\n\n";
}
```

Output:

```
[
    1,
    2,
    3
]
```

Effect of `allow_exceptions` parameter

The example below demonstrates the effect of the `allow_exceptions` parameter in the `parse()` function.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // an invalid JSON text
    std::string text = R"(
    {
        "key": "value without closing quotes
    }
    )";

    // parse with exceptions
    try
    {
        json j = json::parse(text);
    }
    catch (const json::parse_error& e)
    {
        std::cout << e.what() << std::endl;
    }

    // parse without exceptions
    json j = json::parse(text, nullptr, false);

    if (j.is_discarded())
    {
        std::cout << "the input is invalid JSON" << std::endl;
    }
    else
    {
        std::cout << "the input is valid JSON: " << j << std::endl;
    }
}
```

Output:

```
[json.exception.parse_error.101] parse error at line 4, column 0: syntax error while parsing value - invalid string: control character U+000A (LF) must be escaped to \u000A or \n; last read: '"value without closing quotes<U+000A>'
the input is invalid JSON
```

Effect of `ignore_comments` parameter

The example below demonstrates the effect of the `ignore_comments` parameter in the `parse()` function.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    std::string s = R"(
    {
        // update in 2006: removed Pluto
        "planets": ["Mercury", "Venus", "Earth", "Mars",
                    "Jupiter", "Uranus", "Neptune" /*, "Pluto" */]
    }
    )";

    try
    {
        json j = json::parse(s);
    }
    catch (json::exception& e)
    {
        std::cout << e.what() << std::endl;
    }

    json j = json::parse(s,
                         /* callback */ nullptr,
                         /* allow exceptions */ true,
                         /* ignore_comments */ true);
    std::cout << j.dump(2) << '\n';
}
```

Output:

```
[json.exception.parse_error.101] parse error at line 3, column 9: syntax error while parsing object key - invalid literal; last read: '<U+000A>    {<U+000A>        /'; expected string literal
{
  "planets": [
    "Mercury",
    "Venus",
    "Earth",
    "Mars",
    "Jupiter",
    "Uranus",
    "Neptune"
  ]
}
```

Effect of `ignore_trailing_commas` parameter

The example below demonstrates the effect of the `ignore_trailing_commas` parameter in the `parse()` function.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    std::string s = R"(
    {
        "planets": [
            "Mercury",
            "Venus",
            "Earth",
            "Mars",
            "Jupiter",
            "Uranus",
            "Neptune",
        ]
    }
    )";

    try
    {
        json j = json::parse(s);
    }
    catch (json::exception& e)
    {
        std::cout << e.what() << std::endl;
    }

    json j = json::parse(s,
                         /* callback */ nullptr,
                         /* allow exceptions */ true,
                         /* ignore_comments */ false,
                         /* ignore_trailing_commas */ true);
    std::cout << j.dump(2) << '\n';
}
```

Output:

```
[json.exception.parse_error.101] parse error at line 11, column 9: syntax error while parsing value - unexpected ']'; expected '[', '{', or a literal
{
  "planets": [
    "Mercury",
    "Venus",
    "Earth",
    "Mars",
    "Jupiter",
    "Uranus",
    "Neptune"
  ]
}
```

## See also

- [accept](https://json.nlohmann.me/api/basic_json/accept/index.md) - check if the input is valid JSON
- [sax_parse](https://json.nlohmann.me/api/basic_json/sax_parse/index.md) - parse input using the SAX interface
- [operator>>](https://json.nlohmann.me/api/operator_gtgt/index.md) - deserialize from stream

## Version history

- Added in version 1.0.0.
- Overload for contiguous containers (1) added in version 2.0.3.
- Ignoring comments via `ignore_comments` added in version 3.9.0.
- Changed [runtime assertion](https://json.nlohmann.me/features/assertions/index.md) in case of `FILE*` null pointers to exception in version 3.12.0.
- Added `ignore_trailing_commas` in version 3.13.0.
- Extended container support (1) to include types with lvalue-only ADL `begin`/`end` (matching `std::begin`/`std::end` semantics) in version 3.13.0.
- Extended overload (2) to accept heterogeneous iterator+sentinel pairs (C++20 ranges support) in version 3.13.0.

Deprecation

Overload (2) replaces calls to `parse` with a pair of iterators as their first parameter which has been deprecated in version 3.8.0. This overload will be removed in version 4.0.0. Please replace all calls like `parse({ptr, ptr+len}, ...);` with `parse(ptr, ptr+len, ...);`.

You should be warned by your compiler with a `-Wdeprecated-declarations` warning if you are using a deprecated function.
