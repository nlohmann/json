# <small>nlohmann::json_pointer::</small>operator!=

```cpp
// until C++20
template<typename RefStringTypeLhs, typename RefStringTypeRhs>
bool operator!=(
    const json_pointer<RefStringTypeLhs>& lhs,
    const json_pointer<RefStringTypeRhs>& rhs) noexcept;  // (1)

template<typename RefStringTypeLhs, typename StringType>
bool operator!=(
    const json_pointer<RefStringTypeLhs>& lhs,
    const StringType& rhs);                               // (2)

template<typename RefStringTypeRhs, typename StringType>
bool operator!=(
    const StringType& lhs,
    const json_pointer<RefStringTypeRhs>& rhs);           // (2)
```

1. Compares two JSON pointers for inequality by comparing their reference tokens.

2. Compares a JSON pointer and a string or a string and a JSON pointer for inequality by converting the string to a
   JSON pointer and comparing the JSON pointers according to 1.

## Template parameters

`RefStringTypeLhs`, `RefStringTypeRhs`
:   the string type of the left-hand side or right-hand side JSON pointer, respectively

`StringType`
:   the string type derived from the `json_pointer` operand ([`json_pointer::string_t`](string_t.md))

## Parameters

`lhs` (in)
:   first value to consider

`rhs` (in)
:   second value to consider

## Return value

whether the values `lhs`/`*this` and `rhs` are not equal

## Exception safety

1. No-throw guarantee: this function never throws exceptions.
2. Strong exception safety: if an exception occurs, the original value stays intact.

## Exceptions

1. (none)
2. The function can throw the following exceptions:
   - Throws [parse_error.107](../../home/exceptions.md#jsonexceptionparse_error107) if the given JSON pointer `s` is
     nonempty and does not begin with a slash (`/`); see example below.
   - Throws [parse_error.108](../../home/exceptions.md#jsonexceptionparse_error108) if a tilde (`~`) in the given JSON
     pointer `s` is not followed by `0` (representing `~`) or `1` (representing `/`); see example below.

## Complexity

Constant if `lhs` and `rhs` differ in the number of reference tokens, otherwise linear in the number of reference
tokens.

## Notes

!!! note "Operator overload resolution"

    Since C++20 overload resolution will consider the _rewritten candidate_ generated from
    [`operator==`](operator_eq.md).

!!! warning "Deprecation"

    Overload 2 is deprecated and will be removed in a future major version release.

## Examples

??? example "Example: (1) Comparing JSON pointers"

    The example demonstrates comparing JSON pointers.
        
    ```cpp
    --8<-- "examples/json_pointer__operator__notequal.cpp"
    ```
    
    Output:
    
    ```
    --8<-- "examples/json_pointer__operator__notequal.output"
    ```

??? example "Example: (2) Comparing JSON pointers and strings"

    The example demonstrates comparing JSON pointers and strings, and when doing so may raise an exception.
        
    ```cpp
    --8<-- "examples/json_pointer__operator__notequal_stringtype.cpp"
    ```
    
    Output:
    
    ```
    --8<-- "examples/json_pointer__operator__notequal_stringtype.output"
    ```

## Version history

1. Added in version 2.1.0.
2. Added for backward compatibility and deprecated in version 3.11.2.
