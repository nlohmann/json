# nlohmann::basic_json::accept

```
// (1)
template<typename InputType>
static bool accept(InputType&& i,
                   const bool ignore_comments = false,
                   const bool ignore_trailing_commas = false);

// (2)
template<typename IteratorType>
static bool accept(IteratorType first, IteratorType last,
                   const bool ignore_comments = false,
                   const bool ignore_trailing_commas = false);
```

Checks whether the input is valid JSON.

1. Reads from a compatible input.

1. Reads from a pair of character iterators

   The value_type of the iterator must be an integral type with a size of 1, 2, or 4 bytes, which will be interpreted respectively as UTF-8, UTF-16, and UTF-32.

Unlike the [`parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md) function, this function neither throws an exception in case of invalid JSON input (i.e., a parse error) nor creates diagnostic information.

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

## Parameters

`i` (in) : Input to parse from.

`ignore_comments` (in) : whether comments should be ignored and treated like whitespace (`true`) or yield a parse error (`false`); (optional, `false` by default)

`ignore_trailing_commas` (in) : whether trailing commas in arrays or objects should be ignored and treated like whitespace (`true`) or yield a parse error (`false`); (optional, `false` by default)

`first` (in) : iterator to the start of the character range

`last` (in) : iterator to the end of the character range

## Return value

Whether the input is valid JSON.

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

Throws [`parse_error.101`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error101) in case of an empty input like a null `FILE*` or `char*` pointer.

## Complexity

Linear in the length of the input. The parser is a predictive LL(1) parser.

## Notes

A UTF-8 byte order mark is silently ignored.

## Examples

Example

The example below demonstrates the `accept()` function reading from a string.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // a valid JSON text
    auto valid_text = R"(
    {
        "numbers": [1, 2, 3]
    }
    )";

    // an invalid JSON text
    auto invalid_text = R"(
    {
        "strings": ["extra", "comma", ]
    }
    )";

    std::cout << std::boolalpha
              << json::accept(valid_text) << ' '
              << json::accept(invalid_text) << '\n';
}
```

Output:

```
true false
```

## See also

- [parse](https://json.nlohmann.me/api/basic_json/parse/index.md) - deserialize from a compatible input
- [sax_parse](https://json.nlohmann.me/api/basic_json/sax_parse/index.md) - parse input using the SAX interface
- [operator>>](https://json.nlohmann.me/api/operator_gtgt/index.md) - deserialize from stream

## Version history

- Added in version 3.0.0.
- Ignoring comments via `ignore_comments` added in version 3.9.0.
- Changed [runtime assertion](https://json.nlohmann.me/features/assertions/index.md) in case of `FILE*` null pointers to exception in version 3.12.0.
- Added `ignore_trailing_commas` in version 3.13.0.
- Extended container support (1) to include types with lvalue-only ADL `begin`/`end` (matching `std::begin`/`std::end` semantics) in version 3.13.0.

Deprecation

Overload (2) replaces calls to `accept` with a pair of iterators as their first parameter which has been deprecated in version 3.8.0. This overload will be removed in version 4.0.0. Please replace all calls like `accept({ptr, ptr+len}, ...);` with `accept(ptr, ptr+len, ...);`.

You should be warned by your compiler with a `-Wdeprecated-declarations` warning if you are using a deprecated function.
