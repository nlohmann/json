# <small>nlohmann::basic_json::</small>operator!=

```cpp
// until C++20
bool operator!=(const_reference lhs, const_reference rhs) noexcept;   // (1)

template<typename ScalarType>
bool operator!=(const_reference lhs, const ScalarType rhs) noexcept(/* see below */); // (2)

template<typename ScalarType>
bool operator!=(ScalarType lhs, const const_reference rhs) noexcept(/* see below */); // (2)
```

1. Compares two JSON values for inequality. Returns `#!cpp !(lhs == rhs)`.
    - This means the comparison is simply the logical negation of `operator==`, including for special values like `NaN` and `discarded`.

2. Compares a JSON value and a scalar or a scalar and a JSON value for inequality by converting the scalar to a JSON
   value and comparing both JSON values according to 1.

## Template parameters

`ScalarType`
:   a scalar type according to `std::is_scalar<ScalarType>::value`

## Parameters

`lhs` (in)
:   first value to consider 

`rhs` (in)
:   second value to consider 

## Return value

whether the values `lhs`/`*this` and `rhs` are not equal

## Exception safety

1. No-throw guarantee: this function never throws exceptions.
2. No-throw guarantee if converting the scalar to a JSON value cannot throw, as for numbers, Booleans, and
   `#!cpp nullptr`; the function is `#!cpp noexcept` exactly in that case. Otherwise, it throws what the conversion
   throws, for example `std::bad_alloc` when converting a string, or
   [`out_of_range.410`](../../home/exceptions.md#jsonexceptionout_of_range410) for an enum value not mapped by
   [`NLOHMANN_JSON_SERIALIZE_ENUM_STRICT`](../macros/nlohmann_json_serialize_enum_strict.md).

## Complexity

Linear.

## Notes

!!! note "C++20"

    Since C++20, `basic_json` declares no `operator!=`. The compiler rewrites `#!cpp a != b` as `#!cpp !(a == b)`
    using [`operator==`](operator_eq.md), so the result is the same as described above.

!!! note "Comparing `NaN` and `discarded`"

    Since `operator!=` is defined as `!(a == b)`, the behavior for special values follows that of `operator==`:
    
    - For `NaN` values: `NaN == NaN` yields `#!cpp false`, so `NaN != NaN` yields `#!cpp true`.
    - For `discarded` values: `discarded == x` yields `#!cpp false` for any `x`, so `discarded != x` yields `#!cpp true`.

## Examples

??? example "Example: (1) compare JSON values"

    The example demonstrates comparing several JSON types.
        
    ```cpp
    --8<-- "examples/operator__notequal.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/operator__notequal.output"
    ```

??? example "Example: (2) compare JSON values with `#!cpp nullptr`"

    The example demonstrates comparing several JSON types against the null pointer (JSON `#!json null`).
        
    ```cpp
    --8<-- "examples/operator__notequal__nullptr_t.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/operator__notequal__nullptr_t.output"
    ```

## See also

- [operator==](operator_eq.md) comparison: equal
- [operator<=>](operator_spaceship.md) comparison: 3-way (C++20)
- [basic_json_view::operator!=](../basic_json_view/operator_ne.md) - the same comparison on a zero-copy view, without
  building a `basic_json` value for it

## Version history

1. Added in version 1.0.0. Added a C++20 member function in version 3.11.0. Changed in version 3.13.0 to remove
   special-casing for `NaN` and `discarded` values; `operator!=` now consistently means `!(a == b)`. Removed the C++20
   member function in version 3.13.0; since C++20, the compiler rewrites `a != b` using `operator==`.
2. Added in version 1.0.0. Changed in version 3.13.0 to remove special-casing for `NaN` and `discarded` values;
   `operator!=` now consistently means `!(a == b)`. Since C++20, the compiler rewrites `a != b` using `operator==`.
   Made conditionally `#!cpp noexcept` in version 3.13.0; before, a throwing conversion called `std::terminate`.
