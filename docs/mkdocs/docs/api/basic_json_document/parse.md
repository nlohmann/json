# <small>nlohmann::basic_json_document::</small>parse

```cpp
// (1)
template<typename InputType>
static basic_json_document parse(InputType&& input,
                                 const bool allow_exceptions = true,
                                 const bool ignore_comments = false,
                                 const bool ignore_trailing_commas = false);

// (2)
template<typename IteratorType>
static basic_json_document parse(IteratorType first, IteratorType last,
                                 const bool allow_exceptions = true,
                                 const bool ignore_comments = false,
                                 const bool ignore_trailing_commas = false);
```

1. Deserialize from a compatible input, borrowing or owning it depending on its value category and type (see Notes).
2. Deserialize from a pair of input iterators.

Both overloads accept exactly what [`BasicJsonType::parse()`](../basic_json/parse.md) accepts, with the same
`ignore_comments`/`ignore_trailing_commas` options, but build a [`basic_json_document`](index.md) (a flat index into
the input) instead of a tree of `BasicJsonType` values.

## Template parameters

`InputType`
:   A compatible input, for instance:

    - a `#!cpp std::string`, `#!cpp std::string_view`, or a C-style array of characters
    - a pointer to a null-terminated string of single byte characters
    - a container for which `#!cpp obj.data()` and `#!cpp obj.size()` give contiguous single-byte access, e.g.
      `#!cpp std::vector<char>` or `#!cpp std::vector<std::uint8_t>`
    - an `#!cpp std::istream` object, or anything else [`BasicJsonType::parse()`](../basic_json/parse.md) accepts

`IteratorType`
:   a compatible iterator type, for instance a pair of pointers such as `ptr` and `ptr + len`, or a pair of
    `#!cpp std::string::iterator`

## Parameters

`input` (in)
:   Input to parse from.

`allow_exceptions` (in)
:   whether to throw exceptions in case of a parse error (optional, `#!cpp true` by default)

`ignore_comments` (in)
:   whether comments should be ignored and treated like whitespace (`#!cpp true`) or yield a parse error
    (`#!cpp false`); (optional, `#!cpp false` by default)

`ignore_trailing_commas` (in)
:   whether trailing commas in arrays or objects should be ignored and treated like whitespace (`#!cpp true`) or
    yield a parse error (`#!cpp false`); (optional, `#!cpp false` by default)

`first` (in)
:   iterator to the start of a character range

`last` (in)
:   iterator to the end of a character range

## Return value

The parsed document. If `allow_exceptions` is `#!cpp false` and the input is not valid JSON, the returned document is
discarded; see [`is_discarded`](is_discarded.md).

## Exceptions

Throws the same exception [`BasicJsonType::parse()`](../basic_json/parse.md) throws for the same input and options --
the same exception id, message, and position -- because on a failing input the library's own parser is run on the
same bytes to produce the diagnostic. Additionally throws
[`out_of_range.416`](../../home/exceptions.md#jsonexceptionout_of_range416) if the input is 4 GiB or larger, a size
[`BasicJsonType::parse()`](../basic_json/parse.md) does not reject.

## Complexity

Linear in the length of the input.

## Notes

**Ownership.** Whether the document borrows `input` or owns a copy of it depends on its value category and type:

| `input`                                                                             | ownership                                                    |
|--------------------------------------------------------------------------------------|--------------------------------------------------------------|
| lvalue byte container (`std::string`, `std::vector<char>`, ...), `std::string_view`, C string, character array | **borrowed** -- `input` must outlive the document |
| rvalue `#!cpp std::string`                                                            | **owned**, moved in without a copy                            |
| rvalue byte container other than `#!cpp std::string`                                  | **owned**, copied                                             |
| stream, wide string, or anything else read through the general input adapter          | **owned**, read into a buffer (a stream is read to its end)   |

For overload (2), a pair of pointers to single-byte integers (e.g. `#!cpp const char*`, `#!cpp std::uint8_t*`) is
borrowed. From C++20 on, so is any other contiguous iterator over single bytes, such as
`#!cpp std::vector<char>::iterator` or `#!cpp std::string::const_iterator`. Before C++20 these iterators cannot be
told apart from other class-type iterators, so their range is read into an owned buffer, as is any non-contiguous
range (e.g. of a `#!cpp std::list<char>`).

See [`owns_source`](owns_source.md) to check which happened after a call, and the
[feature page](../../features/json_view.md) for the reasoning.

**Numbers.** As for [`BasicJsonType::parse()`](../basic_json/parse.md), an integer literal too large for the 64-bit
integer type becomes a floating-point value.

## Examples

??? example "Example: (1) borrowed vs. owned input, and errors identical to `BasicJsonType::parse()`"

    ```cpp
    --8<-- "examples/basic_json_document__parse.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_document__parse.output"
    ```

??? example "Example: (2) parse an iterator range (no NUL terminator required)"

    ```cpp
    --8<-- "examples/basic_json_document__parse_iterator_pair.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_document__parse_iterator_pair.output"
    ```

## See also

- [parse_copy](parse_copy.md) - deserialize a copy of a compatible input
- [accept](accept.md) - check whether the input is valid JSON
- [read](read.md) - (re-)parse into this document, reusing its memory
- [owns_source](owns_source.md) - return whether the document holds its own copy of the text
- [load](load.md) - read a document from an image instead of parsing JSON text
- [`BasicJsonType::parse`](../basic_json/parse.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
