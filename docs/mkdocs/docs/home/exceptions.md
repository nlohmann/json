# Exceptions

## Overview

### Base type

All exceptions inherit from class `json::exception` (which in turn inherits from `std::exception`). It is used as the base class for all exceptions thrown by the `basic_json` class. This class can hence be used as "wildcard" to catch exceptions.

``` mermaid
classDiagram
  direction LR
    class `std::exception` {
        <<interface>>
    }

    class `json::exception` {
        +const int id
        +const char* what() const
    }

    class `json::parse_error` {
        +const std::size_t byte
    }

    class `json::invalid_iterator`
    class `json::type_error`
    class `json::out_of_range`
    class `json::other_error`

    `std::exception` <|-- `json::exception`
    `json::exception` <|-- `json::parse_error`
    `json::exception` <|-- `json::invalid_iterator`
    `json::exception` <|-- `json::type_error`
    `json::exception` <|-- `json::out_of_range`
    `json::exception` <|-- `json::other_error`
```

### Switch off exceptions

Exceptions are used widely within the library. They can, however, be switched off with either using the compiler flag `-fno-exceptions` or by defining the symbol [`JSON_NOEXCEPTION`](../api/macros/json_noexception.md). In this case, exceptions are replaced by `abort()` calls. You can further control this behavior by defining `JSON_THROW_USER` (overriding `#!cpp throw`), `JSON_TRY_USER` (overriding `#!cpp try`), and `JSON_CATCH_USER` (overriding `#!cpp catch`).

Note that [`JSON_THROW_USER`](../api/macros/json_throw_user.md) should leave the current scope (e.g., by throwing or aborting), as continuing after it may yield undefined behavior.

??? example

    The code below switches off exceptions and creates a log entry with a detailed error message in case of errors.

    ```cpp
    #include <iostream>
    
    #define JSON_TRY_USER if(true)
    #define JSON_CATCH_USER(exception) if(false)
    #define JSON_THROW_USER(exception)                           \
        {std::clog << "Error in " << __FILE__ << ":" << __LINE__ \
                   << " (function " << __FUNCTION__ << ") - "    \
                   << (exception).what() << std::endl;           \
         std::abort();}
    
    #include <nlohmann/json.hpp>
    ```

Note the explanatory [`what()`](https://en.cppreference.com/w/cpp/error/exception/what) string of exceptions is not available for MSVC if exceptions are disabled, see [#2824](https://github.com/nlohmann/json/discussions/2824).

See [documentation of `JSON_TRY_USER`, `JSON_CATCH_USER` and `JSON_THROW_USER`](../api/macros/json_throw_user.md) for more information.

### Extended diagnostic messages

Exceptions in the library are thrown in the local context of the JSON value they are detected. This makes detailed diagnostics messages, and hence debugging, difficult.

??? example

    ```cpp
    --8<-- "examples/diagnostics_standard.cpp"
    ```
    
    Output:

    ```
    --8<-- "examples/diagnostics_standard.output"
    ```

    This exception can be hard to debug if storing the value `#!c "12"` and accessing it is further apart.

To create better diagnostics messages, each JSON value needs a pointer to its parent value such that a global context (i.e., a path from the root value to the value that lead to the exception) can be created. That global context is provided as [JSON Pointer](../features/json_pointer.md).

As this global context comes at the price of storing one additional pointer per JSON value and runtime overhead to maintain the parent relation, extended diagnostics are disabled by default. They can, however, be enabled by defining the preprocessor symbol [`JSON_DIAGNOSTICS`](../api/macros/json_diagnostics.md) to `1` before including `json.hpp`.

??? example

    ```cpp
    --8<-- "examples/diagnostics_extended.cpp"
    ```
    
    Output:

    ```
    --8<-- "examples/diagnostics_extended.output"
    ```

    Now the exception message contains a JSON Pointer `/address/housenumber` that indicates which value has the wrong type.

See [documentation of `JSON_DIAGNOSTICS`](../api/macros/json_diagnostics.md) for more information.

## Parse errors

This exception is thrown by the library when a parse error occurs. Parse errors
can occur during the deserialization of JSON text, CBOR, MessagePack, as well
as when using JSON Patch.

Exceptions have ids 1xx.

!!! info "Byte index"

    Member `byte` holds the byte index of the last read character in the input
    file.

    For an input with n bytes, 1 is the index of the first character and n+1
    is the index of the terminating null byte or the end of file. This also
    holds true when reading a byte vector (CBOR or MessagePack).

??? example

    The following code shows how a `parse_error` exception can be caught.

    ```cpp
    --8<-- "examples/parse_error.cpp"
    ```
    
    Output:

    ```
    --8<-- "examples/parse_error.output"
    ```


### json.exception.parse_error.101

This error indicates a syntax error while deserializing a JSON text. The error message describes that an unexpected token (character) was encountered, and the member `byte` indicates the error position.

!!! failure "Example message"

    Input ended prematurely:

    ```
    [json.exception.parse_error.101] parse error at 2: unexpected end of input; expected string literal
    ```

    No input:

    ```
    [json.exception.parse_error.101] parse error at line 1, column 1: attempting to parse an empty input; check that your input string or stream contains the expected JSON
    ```

    Control character was not escaped:

    ```
    [json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0009 (HT) must be escaped to \u0009 or \\; last read: '"<U+0009>'"
    ```

    String was not closed:

    ```
    [json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: missing closing quote; last read: '"'
    ```

    Invalid number format:

    ```
    [json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid number; expected '+', '-', or digit after exponent; last read: '1E'
    ```

    `\u` was not be followed by four hex digits:

    ```
    [json.exception.parse_error.101] parse error at line 1, column 6: syntax error while parsing value - invalid string: '\u' must be followed by 4 hex digits; last read: '"\u01"'
    ```

    Invalid UTF-8 surrogate pair:

    ```
    [json.exception.parse_error.101] parse error at line 1, column 13: syntax error while parsing value - invalid string: surrogate U+DC00..U+DFFF must follow U+D800..U+DBFF; last read: '"\uD7FF\uDC00'"
    ```

    Invalid UTF-8 byte:

    ```
    [json.exception.parse_error.101] parse error at line 3, column 24: syntax error while parsing value - invalid string: ill-formed UTF-8 byte; last read: '"vous \352t'
    ```

!!! tip

    - Make sure the input is correctly read. Try to write the input to standard output to check if, for instance, the input file was successfully opened.
    - Paste the input to a JSON validator like <http://jsonlint.com> or a tool like [jq](https://stedolan.github.io/jq/).

### json.exception.parse_error.102

JSON uses the `\uxxxx` format to describe Unicode characters. Code points above 0xFFFF are split into two `\uxxxx` entries ("surrogate pairs"). This error indicates that the surrogate pair is incomplete or contains an invalid code point.

!!! failure "Example message"

    ```
    parse error at 14: missing or wrong low surrogate
    ```

!!! note

    This exception is not used any more. Instead [json.exception.parse_error.101](#jsonexceptionparse_error101) with a more detailed description is used.

### json.exception.parse_error.103

Unicode supports code points up to 0x10FFFF. Code points above 0x10FFFF are invalid.

!!! failure "Example message"

    ```
    parse error: code points above 0x10FFFF are invalid
    ```

!!! note

    This exception is not used any more. Instead [json.exception.parse_error.101](#jsonexceptionparse_error101) with a more detailed description is used.

### json.exception.parse_error.104

[RFC 6902](https://tools.ietf.org/html/rfc6902) requires a JSON Patch document to be a JSON document that represents an array of objects.

!!! failure "Example message"

    ```
    [json.exception.parse_error.104] parse error: JSON patch must be an array of objects
    ```

### json.exception.parse_error.105

An operation of a JSON Patch document must contain exactly one "op" member, whose value indicates the operation to perform. Its value must be one of "add", "remove", "replace", "move", "copy", or "test"; other values are errors.

!!! failure "Example message"

    ```
    [json.exception.parse_error.105] parse error: operation 'add' must have member 'value'
    ```
    ```
    [json.exception.parse_error.105] parse error: operation 'copy' must have string member 'from'
    ```
    ```
    [json.exception.parse_error.105] parse error: operation value 'foo' is invalid
    ```

### json.exception.parse_error.106

An array index in a JSON Pointer ([RFC 6901](https://tools.ietf.org/html/rfc6901)) may be `0` or any number without a leading `0`.

!!! failure "Example message"

    ```
    [json.exception.parse_error.106] parse error: array index '01' must not begin with '0'
    ```

### json.exception.parse_error.107

A JSON Pointer must be a Unicode string containing a sequence of zero or more reference tokens, each prefixed by a `/` character.

!!! failure "Example message"

    ```
    [json.exception.parse_error.107] parse error at byte 1: JSON pointer must be empty or begin with '/' - was: 'foo'
    ```

### json.exception.parse_error.108

In a JSON Pointer, only `~0` and `~1` are valid escape sequences.

!!! failure "Example message"

    ```
    [json.exception.parse_error.108] parse error: escape character '~' must be followed with '0' or '1'
    ```

### json.exception.parse_error.109

A JSON Pointer array index must be a number.

!!! failure "Example messages"

    ```
    [json.exception.parse_error.109] parse error: array index 'one' is not a number
    ```
    ```
    [json.exception.parse_error.109] parse error: array index '+1' is not a number
    ```

### json.exception.parse_error.110

When parsing CBOR or MessagePack, the byte vector ends before the complete value has been read.

!!! failure "Example message"

    ```
    [json.exception.parse_error.110] parse error at byte 5: syntax error while parsing CBOR string: unexpected end of input
    ```
    ```
    [json.exception.parse_error.110] parse error at byte 2: syntax error while parsing UBJSON value: expected end of input; last byte: 0x5A
    ```

### json.exception.parse_error.112

An unexpected byte was read in a [binary format](../features/binary_formats/index.md) or length information is invalid ([BSON](../features/binary_formats/bson.md)).

!!! failure "Example messages"

    ```
    [json.exception.parse_error.112] parse error at byte 1: syntax error while parsing CBOR value: invalid byte: 0x1C
    ```
    ```
    [json.exception.parse_error.112] parse error at byte 1: syntax error while parsing MessagePack value: invalid byte: 0xC1
    ```
    ```
    [json.exception.parse_error.112] parse error at byte 4: syntax error while parsing BJData size: expected '#' after type information; last byte: 0x02
    ```
    ```
    [json.exception.parse_error.112] parse error at byte 4: syntax error while parsing UBJSON size: expected '#' after type information; last byte: 0x02
    ```
    ```
    [json.exception.parse_error.112] parse error at byte 10: syntax error while parsing BSON string: string length must be at least 1, is -2147483648
    ```
    ```
    [json.exception.parse_error.112] parse error at byte 15: syntax error while parsing BSON binary: byte array length cannot be negative, is -1
    ```

### json.exception.parse_error.113

While parsing a map key, a value that is not a string has been read.

!!! failure "Example messages"

    ```
    [json.exception.parse_error.113] parse error at byte 2: syntax error while parsing CBOR string: expected length specification (0x60-0x7B) or indefinite string type (0x7F); last byte: 0xFF
    ```
    ```
    [json.exception.parse_error.113] parse error at byte 2: syntax error while parsing MessagePack string: expected length specification (0xA0-0xBF, 0xD9-0xDB); last byte: 0xFF
    ```
    ```
    [json.exception.parse_error.113] parse error at byte 2: syntax error while parsing UBJSON char: byte after 'C' must be in range 0x00..0x7F; last byte: 0x82
    ```

### json.exception.parse_error.114

The parsing of the corresponding BSON record type is not implemented (yet).

!!! failure "Example message"

    ```
    [json.exception.parse_error.114] parse error at byte 5: Unsupported BSON record type 0xFF
    ```

### json.exception.parse_error.115

A UBJSON high-precision number could not be parsed.

!!! failure "Example message"

    ```
    [json.exception.parse_error.115] parse error at byte 5: syntax error while parsing UBJSON high-precision number: invalid number text: 1A
    ```

## Iterator errors

This exception is thrown if iterators passed to a library function do not match
the expected semantics.

Exceptions have ids 2xx.

??? example

    The following code shows how an `invalid_iterator` exception can be caught.

    ```cpp
    --8<-- "examples/invalid_iterator.cpp"
    ```
    
    Output:

    ```
    --8<-- "examples/invalid_iterator.output"
    ```

### json.exception.invalid_iterator.201

The iterators passed to constructor `basic_json(InputIT first, InputIT last)` are not compatible, meaning they do not belong to the same container. Therefore, the range (`first`, `last`) is invalid.

!!! failure "Example message"

    ```
    [json.exception.invalid_iterator.201] iterators are not compatible
    ```

### json.exception.invalid_iterator.202

In the [erase](../api/basic_json/erase.md) or insert function, the passed iterator `pos` does not belong to the JSON value for which the function was called. It hence does not define a valid position for the deletion/insertion.

!!! failure "Example messages"

    ```
    [json.exception.invalid_iterator.202] iterator does not fit current value
    ```
    ```
    [json.exception.invalid_iterator.202] iterators first and last must point to objects
    ```

### json.exception.invalid_iterator.203

Either iterator passed to function [`erase(IteratorType first, IteratorType last`)](../api/basic_json/erase.md) does not belong to the JSON value from which values shall be erased. It hence does not define a valid range to delete values from.

!!! failure "Example message"

    ```
    [json.exception.invalid_iterator.203] iterators do not fit current value
    ```

### json.exception.invalid_iterator.204

When an iterator range for a primitive type (number, boolean, or string) is passed to a constructor or an [erase](../api/basic_json/erase.md) function, this range has to be exactly (`begin(),` `end()),` because this is the only way the single stored value is expressed. All other ranges are invalid.

!!! failure "Example message"

    ```
    [json.exception.invalid_iterator.204] iterators out of range
    ```

### json.exception.invalid_iterator.205

When an iterator for a primitive type (number, boolean, or string) is passed to an [erase](../api/basic_json/erase.md) function, the iterator has to be the `begin()` iterator, because it is the only way to address the stored value. All other iterators are invalid.

!!! failure "Example message"

    ```
    [json.exception.invalid_iterator.205] iterator out of range
    ```

### json.exception.invalid_iterator.206

The iterators passed to constructor `basic_json(InputIT first, InputIT last)` belong to a JSON null value and hence to not define a valid range.

!!! failure "Example message"

    ```
    [json.exception.invalid_iterator.206] cannot construct with iterators from null
    ```

### json.exception.invalid_iterator.207

The `key()` member function can only be used on iterators belonging to a JSON object, because other types do not have a concept of a key.

!!! failure "Example message"

    ```
    [json.exception.invalid_iterator.207] cannot use key() for non-object iterators
    ```


### json.exception.invalid_iterator.208

The `operator[]` to specify a concrete offset cannot be used on iterators belonging to a JSON object, because JSON objects are unordered.

!!! failure "Example message"

    ```
    [json.exception.invalid_iterator.208] cannot use operator[] for object iterators
    ```

### json.exception.invalid_iterator.209

The offset operators (`+`, `-`, `+=`, `-=`) cannot be used on iterators belonging to a JSON object, because JSON objects are unordered.

!!! failure "Example message"

    ```
    [json.exception.invalid_iterator.209] cannot use offsets with object iterators
    ```

### json.exception.invalid_iterator.210

The iterator range passed to the insert function are not compatible, meaning they do not belong to the same container. Therefore, the range (`first`, `last`) is invalid.

!!! failure "Example message"

    ```
    [json.exception.invalid_iterator.210] iterators do not fit
    ```

### json.exception.invalid_iterator.211

The iterator range passed to the insert function must not be a subrange of the container to insert to.

!!! failure "Example message"

    ```
    [json.exception.invalid_iterator.211] passed iterators may not belong to container
    ```

### json.exception.invalid_iterator.212

When two iterators are compared, they must belong to the same container.

!!! failure "Example message"

    ```
    [json.exception.invalid_iterator.212] cannot compare iterators of different containers
    ```

### json.exception.invalid_iterator.213

The order of object iterators cannot be compared, because JSON objects are unordered.

!!! failure "Example message"

    ```
    [json.exception.invalid_iterator.213] cannot compare order of object iterators
    ```

### json.exception.invalid_iterator.214

Cannot get value for iterator: Either the iterator belongs to a null value or it is an iterator to a primitive type (number, boolean, or string), but the iterator is different to `begin()`.

!!! failure "Example message"

    ```
    [json.exception.invalid_iterator.214] cannot get value
    ```

## Type errors

This exception is thrown in case of a type error; that is, a library function is executed on a JSON value whose type does not match the expected semantics.

Exceptions have ids 3xx.

??? example

    The following code shows how a `type_error` exception can be caught.

    ```cpp
    --8<-- "examples/type_error.cpp"
    ```
    
    Output:

    ```
    --8<-- "examples/type_error.output"
    ```

### json.exception.type_error.301

To create an object from an initializer list, the initializer list must consist only of a list of pairs whose first element is a string. When this constraint is violated, an array is created instead.

!!! failure "Example message"

    ```
    [json.exception.type_error.301] cannot create object from initializer list
    ```

### json.exception.type_error.302

During implicit or explicit value conversion, the JSON type must be compatible to the target type. For instance, a JSON string can only be converted into string types, but not into numbers or boolean types.

!!! failure "Example messages"

    ```
    [json.exception.type_error.302] type must be object, but is null
    ```
    ```
    [json.exception.type_error.302] type must be string, but is object
    ```

### json.exception.type_error.303

To retrieve a reference to a value stored in a `basic_json` object with `get_ref`, the type of the reference must match the value type. For instance, for a JSON array, the `ReferenceType` must be `array_t &`.

!!! failure "Example messages"

    ```
    [json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is object
    ```
    ```
    [json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is number"
    ```

### json.exception.type_error.304

The `at()` member functions can only be executed for certain JSON types.

!!! failure "Example messages"

    ```
    [json.exception.type_error.304] cannot use at() with string
    ```
    ```
    [json.exception.type_error.304] cannot use at() with number
    ```

### json.exception.type_error.305

The `operator[]` member functions can only be executed for certain JSON types.

!!! failure "Example messages"

    ```
    [json.exception.type_error.305] cannot use operator[] with a string argument with array
    ```
    ```
    [json.exception.type_error.305] cannot use operator[] with a numeric argument with object
    ```

### json.exception.type_error.306

The `value()` member functions can only be executed for certain JSON types.

!!! failure "Example message"

    ```
    [json.exception.type_error.306] cannot use value() with number
    ```

### json.exception.type_error.307

The [`erase()`](../api/basic_json/erase.md) member functions can only be executed for certain JSON types.

!!! failure "Example message"

    ```
    [json.exception.type_error.307] cannot use erase() with string
    ```

### json.exception.type_error.308

The `push_back()` and `operator+=` member functions can only be executed for certain JSON types.

!!! failure "Example message"

    ```
    [json.exception.type_error.308] cannot use push_back() with string
    ```

### json.exception.type_error.309

The `insert()` member functions can only be executed for certain JSON types.

!!! failure "Example messages"

    ```
    [json.exception.type_error.309] cannot use insert() with array
    ```
    ```
    [json.exception.type_error.309] cannot use insert() with number
    ```

### json.exception.type_error.310

The `swap()` member functions can only be executed for certain JSON types.

!!! failure "Example message"

    ```
    [json.exception.type_error.310] cannot use swap() with number
    ```

### json.exception.type_error.311

The `emplace()` and `emplace_back()` member functions can only be executed for certain JSON types.

!!! failure "Example messages"

    ```
    [json.exception.type_error.311] cannot use emplace() with number
    ```
    ```
    [json.exception.type_error.311] cannot use emplace_back() with number
    ```

### json.exception.type_error.312

The `update()` member functions can only be executed for certain JSON types.

!!! failure "Example message"

    ```
    [json.exception.type_error.312] cannot use update() with array
    ```

### json.exception.type_error.313

The `unflatten` function converts an object whose keys are JSON Pointers back into an arbitrary nested JSON value. The JSON Pointers must not overlap, because then the resulting value would not be well-defined.

!!! failure "Example message"

    ```
    [json.exception.type_error.313] invalid value to unflatten
    ```

### json.exception.type_error.314

The `unflatten` function only works for an object whose keys are JSON Pointers.

!!! failure "Example message"

    Calling `unflatten()` on an array `#!json [1,2,3]`:

    ```
    [json.exception.type_error.314] only objects can be unflattened
    ```

### json.exception.type_error.315

The `unflatten()` function only works for an object whose keys are JSON Pointers and whose values are primitive.

!!! failure "Example message"

    Calling `unflatten()` on an object `#!json {"/1", [1,2,3]}`:

    ```
    [json.exception.type_error.315] values in object must be primitive
    ```

### json.exception.type_error.316

The `dump()` function only works with UTF-8 encoded strings; that is, if you assign a `std::string` to a JSON value, make sure it is UTF-8 encoded.

!!! failure "Example message"

    Calling `dump()` on a JSON value containing an ISO 8859-1 encoded string:
    ```
    [json.exception.type_error.316] invalid UTF-8 byte at index 15: 0x6F
    ```

!!! tip

    - Store the source file with UTF-8 encoding.
    - Pass an error handler as last parameter to the `dump()` function to avoid this exception:
        - `json::error_handler_t::replace` will replace invalid bytes sequences with `U+FFFD` 
        - `json::error_handler_t::ignore` will silently ignore invalid byte sequences

### json.exception.type_error.317

The dynamic type of the object cannot be represented in the requested serialization format (e.g. a raw `true` or `null` JSON object cannot be serialized to BSON)

!!! failure "Example messages"

    Serializing `#!json null` to BSON:
    ```
    [json.exception.type_error.317] to serialize to BSON, top-level type must be object, but is null
    ```
    Serializing `#!json [1,2,3]` to BSON:
    ```
    [json.exception.type_error.317] to serialize to BSON, top-level type must be object, but is array
    ```

!!! tip

    Encapsulate the JSON value in an object. That is, instead of serializing `#!json true`, serialize `#!json {"value": true}`

## Out of range

This exception is thrown in case a library function is called on an input parameter that exceeds the expected range, for instance in case of array indices or nonexisting object keys.

Exceptions have ids 4xx.

??? example

    The following code shows how an `out_of_range` exception can be caught.

    ```cpp
    --8<-- "examples/out_of_range.cpp"
    ```
    
    Output:

    ```
    --8<-- "examples/out_of_range.output"
    ```

### json.exception.out_of_range.401

The provided array index `i` is larger than `size-1`.

!!! failure "Example message"

    ```
    array index 3 is out of range
    ```

### json.exception.out_of_range.402

The special array index `-` in a JSON Pointer never describes a valid element of the array, but the index past the end. That is, it can only be used to add elements at this position, but not to read it.

!!! failure "Example message"

    ```
    array index '-' (3) is out of range
    ```

### json.exception.out_of_range.403

The provided key was not found in the JSON object.

!!! failure "Example message"

    ```
    key 'foo' not found
    ```

### json.exception.out_of_range.404

A reference token in a JSON Pointer could not be resolved.

!!! failure "Example message"

    ```
    unresolved reference token 'foo'
    ```

### json.exception.out_of_range.405

The JSON Patch operations 'remove' and 'add' can not be applied to the root element of the JSON value.

!!! failure "Example message"

    ```
    JSON pointer has no parent
    ```

### json.exception.out_of_range.406

A parsed number could not be stored as without changing it to NaN or INF.

!!! failure "Example message"

    ```
    number overflow parsing '10E1000'
    ```

### json.exception.out_of_range.407

This exception previously indicated that the UBJSON and BSON binary formats did not support integer numbers greater than
9223372036854775807 due to limitations in the implemented mapping. However, these limitations have since been resolved,
and this exception no longer occurs.

!!! success "Exception cannot occur any more"

    - Since version 3.9.0, integer numbers beyond int64 are serialized as high-precision UBJSON numbers.
    - Since version 3.12.0, integer numbers beyond int64 are serialized as uint64 BSON numbers.

### json.exception.out_of_range.408

The size (following `#`) of an UBJSON array or object exceeds the maximal capacity.

!!! failure "Example message"

    ```
    excessive array size: 8658170730974374167
    ```

### json.exception.out_of_range.409

Key identifiers to be serialized to BSON cannot contain code point U+0000, since the key is stored as zero-terminated c-string.

!!! failure "Example message"

    ```
    BSON key cannot contain code point U+0000 (at byte 2)
    ```

## Further exceptions

This exception is thrown in case of errors that cannot be classified with the
other exception types.

Exceptions have ids 5xx.

??? example

    The following code shows how an `other_error` exception can be caught.

    ```cpp
    --8<-- "examples/other_error.cpp"
    ```
    
    Output:

    ```
    --8<-- "examples/other_error.output"
    ```

### json.exception.other_error.501

A JSON Patch operation 'test' failed. The unsuccessful operation is also printed.

!!! failure "Example message"

    Executing `#!json {"op":"test", "path":"/baz", "value":"bar"}` on `#!json {"baz": "qux"}`:

    ```
    [json.exception.other_error.501] unsuccessful: {"op":"test","path":"/baz","value":"bar"}
    ```
