# basic_json::from_bson

```cpp
// (1)
template<typename InputType>
static basic_json from_bson(InputType&& i,
                            const bool strict = true,
                            const bool allow_exceptions = true);
// (2)
template<typename IteratorType>
static basic_json from_bson(IteratorType first, IteratorType last,
                            const bool strict = true,
                            const bool allow_exceptions = true);
```

Deserializes a given input to a JSON value using the BSON (Binary JSON) serialization format.

1. Reads from a compatible input.
2. Reads from an iterator range.

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
:   an input in BSON format convertible to an input adapter

`first` (in)
:   iterator to start of the input

`last` (in)
:   iterator to end of the input

`strict` (in)
:   whether to expect the input to be consumed until EOF (`#!cpp true` by default)

`allow_exceptions` (in)
:   whether to throw exceptions in case of a parse error (optional, `#!cpp true` by default)

## Return value

deserialized JSON value; in case of a parse error and `allow_exceptions` set to `#!cpp false`, the return value will be
`value_t::discarded`.  The latter can be checked with [`is_discarded`](is_discarded.md).

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Complexity

Linear in the size of the input.

## Example

??? example

    The example shows the deserialization of a byte vector in BSON format to a JSON value.
     
    ```cpp
    --8<-- "examples/from_bson.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/from_bson.output"
    ```

## Version history

- Added in version 3.4.0.
