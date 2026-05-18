# <small>nlohmann::basic_json::</small>accept

```cpp
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
2. Reads from a pair of character iterators
    
    The value_type of the iterator must be an integral type with a size of 1, 2, or 4 bytes, which will be interpreted
    respectively as UTF-8, UTF-16, and UTF-32.
    
Unlike the [`parse()`](parse.md) function, this function neither throws an exception in case of invalid JSON input
(i.e., a parse error) nor creates diagnostic information.

## Template parameters

`InputType`
:   A compatible input, for instance:
    
    - an `std::istream` object
    - a `#!c FILE` pointer (throws if null)
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

`ignore_comments` (in)
:   whether comments should be ignored and treated like whitespace (`#!cpp true`) or yield a parse error
    (`#!cpp false`); (optional, `#!cpp false` by default)

`ignore_trailing_commas` (in)
:   whether trailing commas in arrays or objects should be ignored and treated like whitespace (`#!cpp true`) or yield a parse error
    (`#!cpp false`); (optional, `#!cpp false` by default)

`first` (in)
:   iterator to the start of the character range

`last` (in)
:   iterator to the end of the character range

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

## Examples

??? example

    The example below demonstrates the `accept()` function reading from a string.

    ```cpp
    --8<-- "examples/accept__string.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/accept__string.output"
    ```

## See also

- [parse](parse.md) - deserialize from a compatible input
- [operator>>](../operator_gtgt.md) - deserialize from stream

## Version history

- Added in version 3.0.0.
- Ignoring comments via `ignore_comments` added in version 3.9.0.
- Changed [runtime assertion](../../features/assertions.md) in case of `FILE*` null pointers to exception in version 3.12.0.
- Added `ignore_trailing_commas` in version 3.12.1.

!!! warning "Deprecation"

    Overload (2) replaces calls to `accept` with a pair of iterators as their first parameter which has been
    deprecated in version 3.8.0. This overload will be removed in version 4.0.0. Please replace all calls like
    `#!cpp accept({ptr, ptr+len}, ...);` with `#!cpp accept(ptr, ptr+len, ...);`.

    You should be warned by your compiler with a `-Wdeprecated-declarations` warning if you are using a deprecated
    function.
