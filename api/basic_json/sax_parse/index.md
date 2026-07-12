# nlohmann::basic_json::sax_parse

```
// (1)
template <typename InputType, typename SAX>
static bool sax_parse(InputType&& i,
                      SAX* sax,
                      input_format_t format = input_format_t::json,
                      const bool strict = true,
                      const bool ignore_comments = false,
                      const bool ignore_trailing_commas = false);

// (2)
template<class IteratorType, class SAX, class SentinelType = IteratorType>
static bool sax_parse(IteratorType first, SentinelType last,
                      SAX* sax,
                      input_format_t format = input_format_t::json,
                      const bool strict = true,
                      const bool ignore_comments = false,
                      const bool ignore_trailing_commas = false);
```

Read from input and generate SAX events

1. Read from a compatible input.

1. Read from a pair of character iterators, or an iterator and a sentinel of a different type (C++20 ranges support)

   The value_type of the iterator must be an integral type with a size of 1, 2, or 4 bytes, which will be interpreted respectively as UTF-8, UTF-16, and UTF-32. If `SentinelType` differs from `IteratorType`, it must be comparable to the iterator type with `operator!=`.

The SAX event lister must follow the interface of [`json_sax`](https://json.nlohmann.me/api/json_sax/index.md).

## Template parameters

`InputType` : A compatible input, for instance:

```
- an `std::istream` object
- a `FILE` pointer
- a C-style array of characters
- a pointer to a null-terminated string of single byte characters
- a container `obj` for which `begin(obj)` and `end(obj)` produce a valid pair of iterators
  (as found via ADL or member functions, with semantics compatible to `std::begin` and `std::end`)
```

`IteratorType` : a compatible iterator type for overload (2); a pair of character iterators whose `value_type` is an integral type with a size of 1, 2, or 4 bytes (interpreted respectively as UTF-8, UTF-16, and UTF-32)

`SentinelType` : defaults to `IteratorType`; may be a different type comparable to `IteratorType` via `operator!=`, for overload (2), for instance.

```
- a custom sentinel type for C++20 ranges
- `std::default_sentinel_t`, when `IteratorType` is `std::counted_iterator`
```

`SAX` : a class fulfilling the SAX event listener interface; see [`json_sax`](https://json.nlohmann.me/api/json_sax/index.md)

## Parameters

`i` (in) : Input to parse from

`sax` (in) : SAX event listener (must not be null)

`format` (in) : the format to parse (JSON, CBOR, MessagePack, or UBJSON) (optional, `input_format_t::json` by default), see [`input_format_t`](https://json.nlohmann.me/api/basic_json/input_format_t/index.md) for more information

`strict` (in) : whether the input has to be consumed completely (optional, `true` by default)

`ignore_comments` (in) : whether comments should be ignored and treated like whitespace (`true`) or yield a parse error (`false`); (optional, `false` by default)

`ignore_trailing_commas` (in) : whether trailing commas in arrays or objects should be ignored and treated like whitespace (`true`) or yield a parse error (`false`); (optional, `false` by default)

`first` (in) : iterator to the start of a character range

`last` (in) : iterator to the end of a character range, or a sentinel value that compares equal to the end iterator with `operator!=`

## Return value

return value of the last processed SAX event

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

- Throws [`parse_error.101`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error101) in case of an unexpected token, or empty input like a null `FILE*` or `char*` pointer.

## Complexity

Linear in the length of the input. The parser is a predictive LL(1) parser. The complexity can be higher if the SAX consumer `sax` has a super-linear complexity.

## Notes

A UTF-8 byte order mark is silently ignored.

## Examples

Example

The example below demonstrates the `sax_parse()` function reading from string and processing the events with a user-defined SAX event consumer.

```
#include <iostream>
#include <iomanip>
#include <sstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// a simple event consumer that collects string representations of the passed
// values; note inheriting from json::json_sax_t is not required, but can
// help not to forget a required function
class sax_event_consumer : public json::json_sax_t
{
  public:
    std::vector<std::string> events;

    bool null() override
    {
        events.push_back("null()");
        return true;
    }

    bool boolean(bool val) override
    {
        events.push_back("boolean(val=" + std::string(val ? "true" : "false") + ")");
        return true;
    }

    bool number_integer(number_integer_t val) override
    {
        events.push_back("number_integer(val=" + std::to_string(val) + ")");
        return true;
    }

    bool number_unsigned(number_unsigned_t val) override
    {
        events.push_back("number_unsigned(val=" + std::to_string(val) + ")");
        return true;
    }

    bool number_float(number_float_t val, const string_t& s) override
    {
        events.push_back("number_float(val=" + std::to_string(val) + ", s=" + s + ")");
        return true;
    }

    bool string(string_t& val) override
    {
        events.push_back("string(val=" + val + ")");
        return true;
    }

    bool start_object(std::size_t elements) override
    {
        events.push_back("start_object(elements=" + std::to_string(elements) + ")");
        return true;
    }

    bool end_object() override
    {
        events.push_back("end_object()");
        return true;
    }

    bool start_array(std::size_t elements) override
    {
        events.push_back("start_array(elements=" + std::to_string(elements) + ")");
        return true;
    }

    bool end_array() override
    {
        events.push_back("end_array()");
        return true;
    }

    bool key(string_t& val) override
    {
        events.push_back("key(val=" + val + ")");
        return true;
    }

    bool binary(json::binary_t& val) override
    {
        events.push_back("binary(val=[...])");
        return true;
    }

    bool parse_error(std::size_t position, const std::string& last_token, const json::exception& ex) override
    {
        events.push_back("parse_error(position=" + std::to_string(position) + ", last_token=" + last_token + ",\n            ex=" + std::string(ex.what()) + ")");
        return false;
    }
};

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
            "IDs": [116, 943, 234, -38793],
            "DeletionDate": null,
            "Distance": 12.723374634
        }
    }]
    )";

    // create a SAX event consumer object
    sax_event_consumer sec;

    // parse JSON
    bool result = json::sax_parse(text, &sec);

    // output the recorded events
    for (auto& event : sec.events)
    {
        std::cout << event << "\n";
    }

    // output the result of sax_parse
    std::cout << "\nresult: " << std::boolalpha << result << std::endl;
}
```

Output:

```
start_object(elements=18446744073709551615)
key(val=Image)
start_object(elements=18446744073709551615)
key(val=Width)
number_unsigned(val=800)
key(val=Height)
number_unsigned(val=600)
key(val=Title)
string(val=View from 15th Floor)
key(val=Thumbnail)
start_object(elements=18446744073709551615)
key(val=Url)
string(val=http://www.example.com/image/481989943)
key(val=Height)
number_unsigned(val=125)
key(val=Width)
number_unsigned(val=100)
end_object()
key(val=Animated)
boolean(val=false)
key(val=IDs)
start_array(elements=18446744073709551615)
number_unsigned(val=116)
number_unsigned(val=943)
number_unsigned(val=234)
number_integer(val=-38793)
end_array()
key(val=DeletionDate)
null()
key(val=Distance)
number_float(val=12.723375, s=12.723374634)
end_object()
end_object()
parse_error(position=460, last_token=12.723374634<U+000A>        }<U+000A>    }],
            ex=[json.exception.parse_error.101] parse error at line 17, column 6: syntax error while parsing value - unexpected ']'; expected end of input)

result: false
```

## See also

- [parse](https://json.nlohmann.me/api/basic_json/parse/index.md) - deserialize from a compatible input
- [accept](https://json.nlohmann.me/api/basic_json/accept/index.md) - check if the input is valid JSON

## Version history

- Added in version 3.2.0.
- Ignoring comments via `ignore_comments` added in version 3.9.0.
- Added `ignore_trailing_commas` in version 3.13.0.
- Extended container support (1) to include types with lvalue-only ADL `begin`/`end` (matching `std::begin`/`std::end` semantics) in version 3.13.0.
- Extended overload (2) to accept heterogeneous iterator+sentinel pairs (C++20 ranges support) in version 3.13.0.

Deprecation

Overload (2) replaces calls to `sax_parse` with a pair of iterators as their first parameter which has been deprecated in version 3.8.0. This overload will be removed in version 4.0.0. Please replace all calls like `sax_parse({ptr, ptr+len});` with `sax_parse(ptr, ptr+len);`.
