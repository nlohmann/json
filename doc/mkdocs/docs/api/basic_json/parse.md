# basic_json::parse

```cpp
// (1)
template<typename InputType>
static basic_json parse(InputType&& i,
                        const parser_callback_t cb = nullptr,
                        const bool allow_exceptions = true,
                        const bool ignore_comments = false);

// (2)
template<typename IteratorType>
static basic_json parse(IteratorType first, IteratorType last,
                        const parser_callback_t cb = nullptr,
                        const bool allow_exceptions = true,
                        const bool ignore_comments = false);
```

1. Deserialize from a compatible input.
2. Deserialize from a pair of character iterators
    
    The value_type of the iterator must be a integral type with size of 1, 2 or 4 bytes, which will be interpreted
    respectively as UTF-8, UTF-16 and UTF-32.

## Template parameters

`InputType`
:   A compatible input, for instance:
    
    - an `std::istream` object
    - a `FILE` pointer
    - a C-style array of characters
    - a pointer to a null-terminated string of single byte characters
    - an object `obj` for which `begin(obj)` and `end(obj)` produces a valid pair of iterators.

`IteratorType`
:   a compatible iterator type

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

`first` (in)
:   iterator to start of character range

`last` (in)
:   iterator to end of character range

## Return value

Deserialized JSON value; in case of a parse error and `allow_exceptions` set to `#!cpp false`, the return value will be
`value_t::discarded`. The latter can be checked with [`is_discarded`](is_discarded.md).

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Complexity

Linear in the length of the input. The parser is a predictive LL(1) parser. The complexity can be higher if the parser
callback function `cb` or reading from (1) the input `i` or (2) the iterator range [`first`, `last`] has a
super-linear complexity.

## Notes

(1) A UTF-8 byte order mark is silently ignored.

## Examples

??? example "Parsing from a charater array"

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

??? example "Effect of `allow_exceptions` parameter"

    The example below demonstrates the effect of the `allow_exceptions` parameter in the ´parse()` function.

    ```cpp
    --8<-- "examples/parse__allow_exceptions.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/parse__allow_exceptions.output"
    ```

## Version history

- Added in version 1.0.0.
- Overload for contiguous containers (1) added in version 2.0.3.
- Ignoring comments via `ignore_comments` added in version 3.9.0.
