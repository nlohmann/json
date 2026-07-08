# nlohmann::basic_json::end_pos

```
#if JSON_DIAGNOSTIC_POSITIONS
constexpr std::size_t end_pos() const noexcept;
#endif
```

Returns the position immediately following the last character of the JSON string from which the value was parsed from.

| JSON type | return value                      |
| --------- | --------------------------------- |
| object    | position after the closing `}`    |
| array     | position after the closing `]`    |
| string    | position after the closing `"`    |
| number    | position after the last character |
| boolean   | position after `e`                |
| null      | position after `l`                |

## Return value

the position of the character *following* the last character of the given value in the parsed JSON string, if the value was created by the [`parse`](https://json.nlohmann.me/api/basic_json/parse/index.md) function, or `std::string::npos` if the value was constructed otherwise

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Notes

Note

The function is only available if macro [`JSON_DIAGNOSTIC_POSITIONS`](https://json.nlohmann.me/api/macros/json_diagnostic_positions/index.md) has been defined to `1` before including the library header.

Invalidation

The returned positions are only valid as long as the JSON value is not changed. The positions are *not* updated when the JSON value is changed.

## Examples

Example

```
#include <iostream>

#define JSON_DIAGNOSTIC_POSITIONS 1
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    std::string json_string = R"(
    {
        "address": {
            "street": "Fake Street",
            "housenumber": 1
        }
    }
    )";
    json j = json::parse(json_string);

    std::cout << "Root diagnostic positions: \n";
    std::cout << "\tstart_pos: " << j.start_pos() << '\n';
    std::cout << "\tend_pos:" << j.end_pos() << "\n";
    std::cout << "Original string: \n";
    std::cout << "{\n        \"address\": {\n            \"street\": \"Fake Street\",\n            \"housenumber\": 1\n        }\n    }" << "\n";
    std::cout << "Parsed string: \n";
    std::cout << json_string.substr(j.start_pos(), j.end_pos() - j.start_pos()) << "\n\n";

    std::cout << "address diagnostic positions: \n";
    std::cout << "\tstart_pos:" << j["address"].start_pos() << '\n';
    std::cout << "\tend_pos:" << j["address"].end_pos() << "\n\n";
    std::cout << "Original string: \n";
    std::cout << "{            \"street\": \"Fake Street\",\n            \"housenumber\": 1\n        }" << "\n";
    std::cout << "Parsed string: \n";
    std::cout << json_string.substr(j["address"].start_pos(), j["address"].end_pos() - j["address"].start_pos()) << "\n\n";

    std::cout << "street diagnostic positions: \n";
    std::cout << "\tstart_pos:" << j["address"]["street"].start_pos() << '\n';
    std::cout << "\tend_pos:" << j["address"]["street"].end_pos() << "\n\n";
    std::cout << "Original string: \n";
    std::cout << "\"Fake Street\"" << "\n";
    std::cout << "Parsed string: \n";
    std::cout << json_string.substr(j["address"]["street"].start_pos(), j["address"]["street"].end_pos() - j["address"]["street"].start_pos()) << "\n\n";

    std::cout << "housenumber diagnostic positions: \n";
    std::cout << "\tstart_pos:" << j["address"]["housenumber"].start_pos() << '\n';
    std::cout << "\tend_pos:" << j["address"]["housenumber"].end_pos() << "\n\n";
    std::cout << "Original string: \n";
    std::cout << "1" << "\n";
    std::cout << "Parsed string: \n";
    std::cout << json_string.substr(j["address"]["housenumber"].start_pos(), j["address"]["housenumber"].end_pos() - j["address"]["housenumber"].start_pos()) << "\n\n";
}
```

Output:

```
Root diagnostic positions: 
    start_pos: 5
    end_pos:109
Original string: 
{
        "address": {
            "street": "Fake Street",
            "housenumber": 1
        }
    }
Parsed string: 
{
        "address": {
            "street": "Fake Street",
            "housenumber": 1
        }
    }

address diagnostic positions: 
    start_pos:26
    end_pos:103

Original string: 
{            "street": "Fake Street",
            "housenumber": 1
        }
Parsed string: 
{
            "street": "Fake Street",
            "housenumber": 1
        }

street diagnostic positions: 
    start_pos:50
    end_pos:63

Original string: 
"Fake Street"
Parsed string: 
"Fake Street"

housenumber diagnostic positions: 
    start_pos:92
    end_pos:93

Original string: 
1
Parsed string: 
1
```

The output shows the start/end positions of all the objects and fields in the JSON string.

## See also

- [start_pos](https://json.nlohmann.me/api/basic_json/start_pos/index.md) to access the start position
- [JSON_DIAGNOSTIC_POSITIONS](https://json.nlohmann.me/api/macros/json_diagnostic_positions/index.md) for an overview of the diagnostic positions

## Version history

- Added in version 3.12.0.
