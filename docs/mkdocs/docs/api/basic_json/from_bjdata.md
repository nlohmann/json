# <small>nlohmann::basic_json::</small>from_bjdata

```cpp
// (1)
template<typename InputType>
static basic_json from_bjdata(InputType&& i,
                              const bool strict = true,
                              const bool allow_exceptions = true);
// (2)
template<typename IteratorType>
static basic_json from_bjdata(IteratorType first, IteratorType last,
                              const bool strict = true,
                              const bool allow_exceptions = true);
```

Deserializes a given input to a JSON value using the BJData (Binary JData) serialization format.

1. Reads from a compatible input.
2. Reads from an iterator range.

The exact mapping and its limitations are described on a [dedicated page](../../features/binary_formats/bjdata.md).

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
:   an input in BJData format convertible to an input adapter

`first` (in)
:   iterator to the start of the input

`last` (in)
:   iterator to the end of the input

`strict` (in)
:   whether to expect the input to be consumed until EOF (`#!cpp true` by default)

`allow_exceptions` (in)
:   whether to throw exceptions in case of a parse error (optional, `#!cpp true` by default)

## Return value

deserialized JSON value; in case of a parse error and `allow_exceptions` set to `#!cpp false`, the return value will be
`value_t::discarded`. The latter can be checked with [`is_discarded`](is_discarded.md).

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

- Throws [parse_error.110](../../home/exceptions.md#jsonexceptionparse_error110) if the given input ends prematurely or
  the end of the file was not reached when `strict` was set to true
- Throws [parse_error.112](../../home/exceptions.md#jsonexceptionparse_error112) if a parse error occurs
- Throws [parse_error.113](../../home/exceptions.md#jsonexceptionparse_error113) if a string could not be parsed
  successfully

## Complexity

Linear in the size of the input.

## Examples

??? example

    The example shows the deserialization of a byte vector in BJData format to a JSON value.
     
    ```cpp
    --8<-- "examples/from_bjdata.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/from_bjdata.output"
    ```

## Version history

- Added in version 3.11.0.
