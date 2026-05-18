# <small>nlohmann::basic_json::</small>parse

```cpp
// (1)
template<typename InputType>
static basic_json parse(InputType&& i,
                        const parser_callback_t cb = nullptr,
                        const bool allow_exceptions = true,
                        const bool ignore_comments = false,
                        const bool ignore_trailing_commas = false);

// (2)
template<typename IteratorType>
static basic_json parse(IteratorType first, IteratorType last,
                        const parser_callback_t cb = nullptr,
                        const bool allow_exceptions = true,
                        const bool ignore_comments = false,
                        const bool ignore_trailing_commas = false);
```

1. Deserialize from a compatible input.
2. Deserialize from a pair of character iterators
    
    The `value_type` of the iterator must be an integral type with size of 1, 2, or 4 bytes, which will be interpreted
    respectively as UTF-8, UTF-16, and UTF-32.

## Template parameters

`InputType`
:   A compatible input, for instance:
    
    - an `std::istream` object
    - a `FILE` pointer (throws if null)
    - a C-style array of characters
    - a pointer to a null-terminated string of single byte characters (throws if null)
    - a `std::string`
    - an object `obj` for which `begin(obj)` and `end(obj)` produces a valid pair of iterators.

`IteratorType`
:   a compatible iterator type, for instance.

    - a pair of `std::string::iterator` or `std::vector<std::uint8_t>::iterator`
    - a pair of pointers such as `ptr` and `ptr + len`

## Parameters

`i` (in)
:   Input to parse from.

`cb` (in)
:   a parser callback function of type [`parser_callback_t`](parser_callback_t.md) which is used to control the
    deserialization by filtering unwanted values (optional)

`allow_exceptions` (in)
:    whether to throw exceptions in case of a parse error (optional, `#!cpp true` by default)

`ignore_comments` (in)
:   whether comments should be ignored and treated like whitespace (`#!cpp true`) or yield a parse error
    (`#!cpp false`); (optional, `#!cpp false` by default)

`ignore_trailing_commas` (in)
:   whether trailing commas in arrays or objects should be ignored and treated like whitespace (`#!cpp true`) or yield a parse error
    (`#!cpp false`); (optional, `#!cpp false` by default)

`first` (in)
:   iterator to the start of a character range

`last` (in)
:   iterator to the end of a character range

## Return value

Deserialized JSON value; in case of a parse error and `allow_exceptions` set to `#!cpp false`, the return value will be
`value_t::discarded`. The latter can be checked with [`is_discarded`](is_discarded.md).

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

- Throws [`parse_error.101`](../../home/exceptions.md#jsonexceptionparse_error101) in case of an unexpected token, or
  empty input like a null `FILE*` or `char*` pointer.
- Throws [`parse_error.102`](../../home/exceptions.md#jsonexceptionparse_error102) if `to_unicode` fails or surrogate
  error.
- Throws [`parse_error.103`](../../home/exceptions.md#jsonexceptionparse_error103) if `to_unicode` fails.

## Complexity

Linear in the length of the input. The parser is a predictive LL(1) parser. The complexity can be higher if the parser
callback function `cb` or reading from (1) the input `i` or (2) the iterator range [`first`, `last`] has a
super-linear complexity.

## Notes

A UTF-8 byte order mark is silently ignored.

## Examples

??? example "Parsing from a character array"

    The example below demonstrates the `parse()` function reading from an array.

    ```cpp
    --8<-- "examples/parse__array__parser_callback_t.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/parse__array__parser_callback_t.output"
    ```

??? example "Parsing from a string"

    The example below demonstrates the `parse()` function with and without callback function.

    ```cpp
    --8<-- "examples/parse__string__parser_callback_t.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/parse__string__parser_callback_t.output"
    ```

??? example "Parsing from an input stream"

    The example below demonstrates the `parse()` function with and without callback function.

    ```cpp
    --8<-- "examples/parse__istream__parser_callback_t.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/parse__istream__parser_callback_t.output"
    ```

??? example "Parsing from a contiguous container"

    The example below demonstrates the `parse()` function reading from a contiguous container.

    ```cpp
    --8<-- "examples/parse__contiguouscontainer__parser_callback_t.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/parse__contiguouscontainer__parser_callback_t.output"
    ```

??? example "Parsing from a non-null-terminated string"

    The example below demonstrates the `parse()` function reading from a string that is not null-terminated.

    ```cpp
    --8<-- "examples/parse__pointers.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/parse__pointers.output"
    ```

??? example "Parsing from an iterator pair"

    The example below demonstrates the `parse()` function reading from an iterator pair.

    ```cpp
    --8<-- "examples/parse__iterator_pair.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/parse__iterator_pair.output"
    ```

??? example "Effect of `allow_exceptions` parameter"

    The example below demonstrates the effect of the `allow_exceptions` parameter in the ´parse()` function.

    ```cpp
    --8<-- "examples/parse__allow_exceptions.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/parse__allow_exceptions.output"
    ```

??? example "Effect of `ignore_comments` parameter"

    The example below demonstrates the effect of the `ignore_comments` parameter in the `parse()` function.

    ```cpp
    --8<-- "examples/comments.cpp"
    ```

    Output:

    ```
    --8<-- "examples/comments.output"
    ```

??? example "Effect of `ignore_trailing_commas` parameter"

    The example below demonstrates the effect of the `ignore_trailing_commas` parameter in the `parse()` function.

    ```cpp
    --8<-- "examples/trailing_commas.cpp"
    ```

    Output:

    ```
    --8<-- "examples/trailing_commas.output"
    ```

## See also

- [accept](accept.md) - check if the input is valid JSON
- [operator>>](../operator_gtgt.md) - deserialize from stream

## Version history

- Added in version 1.0.0.
- Overload for contiguous containers (1) added in version 2.0.3.
- Ignoring comments via `ignore_comments` added in version 3.9.0.
- Changed [runtime assertion](../../features/assertions.md) in case of `FILE*` null pointers to exception in version 3.12.0.
- Added `ignore_trailing_commas` in version 3.12.1.

!!! warning "Deprecation"

    Overload (2) replaces calls to `parse` with a pair of iterators as their first parameter which has been
    deprecated in version 3.8.0. This overload will be removed in version 4.0.0. Please replace all calls like
    `#!cpp parse({ptr, ptr+len}, ...);` with `#!cpp parse(ptr, ptr+len, ...);`.

    You should be warned by your compiler with a `-Wdeprecated-declarations` warning if you are using a deprecated
    function.
