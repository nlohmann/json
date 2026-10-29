# <small>nlohmann::json_sax::</small>key

```cpp
virtual bool key(string_t& val) = 0;
```

An object key was read.

## Parameters

`val` (in)
:   object key

## Return value

Whether parsing should proceed.

## Notes

It is safe to move the passed object key value.

When parsing JSON text, `val` is the decoded object name, not its spelling in the input:

- All escape sequences (`\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r`, `\t`, `\uXXXX`, and surrogate pairs) are
  decoded, and `\uXXXX` escapes are stored as UTF-8. Different spellings of the same name, such as `#!json "/"`
  and `#!json "\/"`, or `#!json "\u00e9"` and `#!json "\u00E9"`, yield identical strings. An escaped `\u0000` yields
  an embedded NUL byte.
- The name is scanned and validated completely before `key` is called. If it contains an invalid escape sequence, an
  unpaired surrogate, a control character, or ill-formed UTF-8, the parse fails with a
  [`parse_error`](../../home/exceptions.md#parse-errors), and `key` is not called for it.
- No Unicode normalization or case conversion is applied: names that differ in any byte are different strings.
- `key` is called before the following `:` is read, so a parse error may still follow for the same member.
- A name that occurs several times in the same object is passed once per occurrence.

For the binary formats, object keys contain no escape sequences. For CBOR, MessagePack, UBJSON, and BSON, `val` holds
the bytes stored in the input, and [`sax_parse`](../basic_json/sax_parse.md) passes them unchanged, without checking them
for valid UTF-8. BON8 encodes characters itself, so an ill-formed name is a parse error and `key` is not called for it.

## Examples

??? example

    The example below shows how the SAX interface is used.

    ```cpp
    #include <iostream>
    #include <iomanip>
    #include <sstream>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
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
        const auto* text = R"(
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
        std::cout << "\nresult: " << std::boolalpha << result << '\n';
    }
    
    ```
    
    Output:
    
    ```json
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

- [`start_object`](start_object.md) - the beginning of an object was read
- [`end_object`](end_object.md) - the end of an object was read
- [`sax_parse`](../basic_json/sax_parse.md) - SAX parser
- [SAX Interface](../../features/parsing/sax_interface.md) - guide to event-based parsing

## Version history

- Added in version 3.2.0.
- The behavior described in the notes above (decoded names, validation before `key` is called, no normalization, `key`
  before the `:` check, one call per duplicate, bytes of binary formats passed unchanged) is the same in all versions
  from 3.2.0 on, and for the `key` event of a [parser callback](../basic_json/parser_callback_t.md) from 3.0.0 on. BSON
  is only supported from version 3.4.0, and BON8 only from version 3.13.0.
