# nlohmann::basic_json::dump

```
string_t dump(const int indent = -1,
              const char indent_char = ' ',
              const bool ensure_ascii = false,
              const error_handler_t error_handler = error_handler_t::strict) const;
```

Serialization function for JSON values. The function tries to mimic Python's [`json.dumps()` function](https://docs.python.org/2/library/json.html#json.dump), and currently supports its `indent` and `ensure_ascii` parameters.

## Parameters

`indent` (in) : If `indent` is nonnegative, then array elements and object members will be pretty-printed with that indent level. An indent level of `0` will only insert newlines. `-1` (the default) selects the most compact representation.

`indent_char` (in) : The character to use for indentation if `indent` is greater than `0`. The default is (space).

`ensure_ascii` (in) : If `ensure_ascii` is true, all non-ASCII characters in the output are escaped with `\uXXXX` sequences, and the result consists of ASCII characters only.

`error_handler` (in) : how to react on decoding errors; there are three possible values (see [`error_handler_t`](https://json.nlohmann.me/api/basic_json/error_handler_t/index.md): `strict` (throws an exception in case a decoding error occurs; default), `replace` (replace invalid UTF-8 sequences with U+FFFD), and `ignore` (ignore invalid UTF-8 sequences during serialization; all valid bytes are copied to the output unchanged, and invalid bytes are dropped)).

## Return value

string containing the serialization of the JSON value

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes to any JSON value.

## Exceptions

Throws [`type_error.316`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error316) if a string stored inside the JSON value is not UTF-8 encoded and `error_handler` is set to `strict`

## Complexity

Linear.

## Notes

Binary values are serialized as an object containing two keys:

- "bytes": an array of bytes as integers
- "subtype": the subtype as integer or `null` if the binary has no subtype

## Examples

Example

The following example shows the effect of different `indent`, `indent_char`, and `ensure_ascii` parameters to the result of the serialization.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON values
    json j_object = {{"one", 1}, {"two", 2}};
    json j_array = {1, 2, 4, 8, 16};
    json j_string = "Hellö 😀!";

    // call dump()
    std::cout << "objects:" << '\n'
              << j_object.dump() << "\n\n"
              << j_object.dump(-1) << "\n\n"
              << j_object.dump(0) << "\n\n"
              << j_object.dump(4) << "\n\n"
              << j_object.dump(1, '\t') << "\n\n";

    std::cout << "arrays:" << '\n'
              << j_array.dump() << "\n\n"
              << j_array.dump(-1) << "\n\n"
              << j_array.dump(0) << "\n\n"
              << j_array.dump(4) << "\n\n"
              << j_array.dump(1, '\t') << "\n\n";

    std::cout << "strings:" << '\n'
              << j_string.dump() << '\n'
              << j_string.dump(-1, ' ', true) << '\n';

    // create JSON value with invalid UTF-8 byte sequence
    json j_invalid = "ä\xA9ü";
    try
    {
        std::cout << j_invalid.dump() << std::endl;
    }
    catch (const json::type_error& e)
    {
        std::cout << e.what() << std::endl;
    }

    std::cout << "string with replaced invalid characters: "
              << j_invalid.dump(-1, ' ', false, json::error_handler_t::replace)
              << "\nstring with ignored invalid characters: "
              << j_invalid.dump(-1, ' ', false, json::error_handler_t::ignore)
              << '\n';
}
```

Output:

```
objects:
{"one":1,"two":2}

{"one":1,"two":2}

{
"one": 1,
"two": 2
}

{
    "one": 1,
    "two": 2
}

{
    "one": 1,
    "two": 2
}

arrays:
[1,2,4,8,16]

[1,2,4,8,16]

[
1,
2,
4,
8,
16
]

[
    1,
    2,
    4,
    8,
    16
]

[
    1,
    2,
    4,
    8,
    16
]

strings:
"Hellö 😀!"
"Hell\u00f6 \ud83d\ude00!"
[json.exception.type_error.316] invalid UTF-8 byte at index 2: 0xA9
string with replaced invalid characters: "ä�ü"
string with ignored invalid characters: "äü"
```

## See also

- [to_string](https://json.nlohmann.me/api/basic_json/to_string/index.md) returns a string representation of a JSON value
- [operator\<<](https://json.nlohmann.me/api/operator_ltlt/index.md) serialize to stream
- [Serialization](https://json.nlohmann.me/features/serialization/index.md) - the serialization article

## Version history

- Added in version 1.0.0.
- Indentation character `indent_char`, option `ensure_ascii` and exceptions added in version 3.0.0.
- Error handlers added in version 3.4.0.
- Serialization of binary values added in version 3.8.0.
