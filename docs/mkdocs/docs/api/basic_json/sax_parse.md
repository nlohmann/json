# <small>nlohmann::basic_json::</small>sax_parse

```cpp
// (1)
template <typename InputType, typename SAX>
static bool sax_parse(InputType&& i,
                      SAX* sax,
                      input_format_t format = input_format_t::json,
                      const bool strict = true,
                      const bool ignore_comments = false);

// (2)
template<class IteratorType, class SAX>
static bool sax_parse(IteratorType first, IteratorType last,
                      SAX* sax,
                      input_format_t format = input_format_t::json,
                      const bool strict = true,
                      const bool ignore_comments = false);
```

Read from input and generate SAX events

1. Read from a compatible input.
2. Read from a pair of character iterators
    
    The value_type of the iterator must be an integral type with size of 1, 2 or 4 bytes, which will be interpreted
    respectively as UTF-8, UTF-16 and UTF-32.

The SAX event lister must follow the interface of [`json_sax`](../json_sax/index.md).

## Template parameters

`InputType`
:   A compatible input, for instance:
    
    - an `std::istream` object
    - a `FILE` pointer
    - a C-style array of characters
    - a pointer to a null-terminated string of single byte characters
    - an object `obj` for which `begin(obj)` and `end(obj)` produces a valid pair of
      iterators.

`IteratorType`
:   Description

`SAX`
:   Description

## Parameters

`i` (in)
:   Input to parse from.

`sax` (in)
:   SAX event listener

`format` (in)
:    the format to parse (JSON, CBOR, MessagePack, or UBJSON) (optional, `input_format_t::json` by default), see
     [`input_format_t`](input_format_t.md) for more information

`strict` (in)
:   whether the input has to be consumed completely (optional, `#!cpp true` by default)

`ignore_comments` (in)
:   whether comments should be ignored and treated like whitespace (`#!cpp true`) or yield a parse error
    (`#!cpp false`); (optional, `#!cpp false` by default)

`first` (in)
:   iterator to start of character range

`last` (in)
:   iterator to end of character range

## Return value

return value of the last processed SAX event

## Exception safety

## Complexity

Linear in the length of the input. The parser is a predictive LL(1) parser. The complexity can be higher if the SAX
consumer `sax` has a super-linear complexity.

## Notes

A UTF-8 byte order mark is silently ignored.

## Examples

??? example

    The example below demonstrates the `sax_parse()` function reading from string and processing the events with a
    user-defined SAX event consumer.
    
    ```cpp
    --8<-- "examples/sax_parse.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/sax_parse.output"
    ```

## Version history

- Added in version 3.2.0.
- Ignoring comments via `ignore_comments` added in version 3.9.0.

!!! warning "Deprecation"

    Overload (2) replaces calls to `sax_parse` with a pair of iterators as their first parameter which has been
    deprecated in version 3.8.0. This overload will be removed in version 4.0.0. Please replace all calls like
    `#!cpp sax_parse({ptr, ptr+len});` with `#!cpp sax_parse(ptr, ptr+len);`.
