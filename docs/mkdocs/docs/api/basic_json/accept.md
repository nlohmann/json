# <small>nlohmann::basic_json::</small>accept

```cpp
// (1)
template<typename InputType>
static bool accept(InputType&& i,
                   const bool ignore_comments = false,
                   const bool ignore_trailing_commas = false);

// (2)
template<typename IteratorType, typename SentinelType = IteratorType>
static bool accept(IteratorType first, SentinelType last,
                   const bool ignore_comments = false,
                   const bool ignore_trailing_commas = false);
```

Checks whether the input is valid JSON.

1. Reads from a compatible input.
2. Reads from a pair of character iterators, or an iterator and a sentinel of a different type (C++20 ranges support)
    
    The value_type of the iterator must be an integral type with a size of 1, 2, or 4 bytes, which will be interpreted
    respectively as UTF-8, UTF-16, and UTF-32. If `SentinelType` differs from `IteratorType`, it must be comparable to
    the iterator type with `operator!=`.
    
    Ill-formed UTF-16 and UTF-32 sequences are rejected: a lone surrogate, a high surrogate that is not followed by its
    low surrogate, and a code point above `U+10FFFF` all make this function return `false`.

Unlike the [`parse()`](parse.md) function, this function neither throws an exception in case of invalid JSON input
(i.e., a parse error) nor creates diagnostic information.

## Template parameters

`InputType`
:   A compatible input, for instance:
    
    - an `std::istream` object
    - a `#!c FILE` pointer (throws if null)
    - a C-style array of characters
    - a pointer to a null-terminated string of single byte characters (throws if null)
    - a `std::string` or a `std::string_view` (C++17)
    - a container `obj` for which `begin(obj)` and `end(obj)` produce a valid pair of iterators
      (as found via ADL or member functions, with semantics compatible to `std::begin` and `std::end`)
    - wide characters (`wchar_t`, `char16_t`, `char32_t`), which are converted to UTF-8: a wide string object
      (`std::wstring`, `std::u16string`, `std::u32string`) or an array (e.g. a wide string literal); a pointer to a
      null-terminated wide string (e.g. `std::u16string::c_str()`) is not supported

`IteratorType`
:   a compatible iterator type, for instance.

    - a pair of `std::string::iterator` or `std::vector<std::uint8_t>::iterator`
    - a pair of pointers such as `ptr` and `ptr + len`

`SentinelType`
:   defaults to `IteratorType`; may be a different type comparable to `IteratorType` via `operator!=`, for instance.

    - a custom sentinel type for C++20 ranges
    - `std::default_sentinel_t`, when `IteratorType` is `std::counted_iterator`

## Parameters

`i` (in)
:   Input to parse from.

`ignore_comments` (in)
:   whether comments should be ignored and treated like whitespace (`#!cpp true`) or yield a parse error
    (`#!cpp false`); (optional, `#!cpp false` by default)

`ignore_trailing_commas` (in)
:   whether trailing commas in arrays or objects should be ignored and treated like whitespace (`#!cpp true`) or yield a parse error
    (`#!cpp false`); (optional, `#!cpp false` by default)

`first` (in)
:   iterator to the start of the character range

`last` (in)
:   iterator to the end of the character range, or a sentinel value that compares equal to the end iterator with `operator!=`

## Return value

Whether the input is valid JSON.

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

Throws [`parse_error.101`](../../home/exceptions.md#jsonexceptionparse_error101) in case of an empty input like a null `#!c FILE*` or `#!c char*` pointer.

## Complexity

Linear in the length of the input. The parser is a predictive LL(1) parser.

## Notes

A UTF-8 byte order mark is silently ignored.

By default, a `'\0'` (NUL) byte anywhere in the input is treated as end of input, rather than as an ordinary (and,
outside of a string, invalid) byte; see the [FAQ entry](../../home/faq.md#nul-bytes-in-the-input) for details and the
[`JSON_STRICT_NUL_HANDLING`](../macros/json_strict_nul_handling.md) macro to opt into rejecting it instead.

## Examples

??? example "Example: (1) reading from a string"

    The example below demonstrates the `accept()` function reading from a string.

    ```cpp
    --8<-- "examples/accept__string.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/accept__string.output"
    ```

??? example "Example: (2) reading from an iterator pair"

    The example below demonstrates the `accept()` function reading from an iterator pair. Only the first call covers
    exactly the JSON text; the second one also covers the trailing bytes and is therefore rejected.

    ```cpp
    --8<-- "examples/accept__iterator_pair.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/accept__iterator_pair.output"
    ```

??? example "Example: (3) reading from UTF-16 strings"

    The encoding is deduced from the character type of the input. String literals like `u"..."`, `U"..."`, and
    `L"..."` work as well.

    ```cpp
    --8<-- "examples/accept__wide_string.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/accept__wide_string.output"
    ```

## See also

- [`parse`](parse.md) - deserialize from a compatible input
- [`sax_parse`](sax_parse.md) - parse input using the SAX interface
- [`operator>>`](../operator_gtgt.md) - deserialize from stream
- [`JSON_STRICT_NUL_HANDLING`](../macros/json_strict_nul_handling.md) - opt in to rejecting a NUL byte in the input
  instead of treating it as end of input
- [`JSON_DISABLE_STREAM_BULK_SCAN`](../macros/json_disable_stream_bulk_scan.md) - read a `std::istream` one character
  at a time
- [`JSON_DISABLE_UNLOCKED_FILE_IO`](../macros/json_disable_unlocked_file_io.md) - read a `FILE*` with the locking stdio
  functions
- [Parsing](../../features/parsing/index.md) - overview of the parsing functions
- [Comments](../../features/comments.md) - ignore `//` and `/* */` comments while parsing
- [Trailing Commas](../../features/trailing_commas.md) - accept trailing commas in arrays and objects
- [Parsing and Exceptions](../../features/parsing/parse_exceptions.md) - handling parse errors and locating them in the input
- [Parsing Untrusted Input](../../features/parsing/untrusted_input.md) - limits and checks for input you do not control

## Version history

- Added in version 3.0.0.
- Ignoring comments via `ignore_comments` added in version 3.9.0.
- Changed [runtime assertion](../../features/assertions.md) in case of `FILE*` null pointers to exception in version 3.12.0.
- Added `ignore_trailing_commas` in version 3.13.0.
- Extended container support (1) to include types with lvalue-only ADL `begin`/`end` (matching `std::begin`/`std::end` semantics) in version 3.13.0.
- Extended overload (2) to accept heterogeneous iterator+sentinel pairs (C++20 ranges support) in version 3.13.0.
- `JSON_STRICT_NUL_HANDLING` added in version 3.13.0 to optionally reject a NUL byte in the input instead of treating
  it as end of input; planned to become the default in version 4.0.0.
- Parsing from an `std::istream` scans the characters in its stream buffer in bulk in version 3.13.0
  ([`JSON_DISABLE_STREAM_BULK_SCAN`](../macros/json_disable_stream_bulk_scan.md)).
- Parsing from a `FILE*` locks the file once instead of once per character in version 3.13.0
  ([`JSON_DISABLE_UNLOCKED_FILE_IO`](../macros/json_disable_unlocked_file_io.md)).
- Ill-formed UTF-16 and UTF-32 input (a lone surrogate, a high surrogate that is not followed by its low surrogate, or
  a code point above `U+10FFFF`) is rejected in version 3.13.0; before that, some such sequences were accepted or
  ended the input silently.

!!! warning "Deprecation"

    Overload (2) replaces calls to `accept` with a pair of iterators as their first parameter which has been
    deprecated in version 3.8.0. This overload will be removed in version 4.0.0. Please replace all calls like
    `#!cpp accept({ptr, ptr+len}, ...);` with `#!cpp accept(ptr, ptr+len, ...);`.

    You should be warned by your compiler with a `-Wdeprecated-declarations` warning if you are using a deprecated
    function.

    See the [migration guide](../../integration/migration_guide.md#parsing) for how to update existing code.
