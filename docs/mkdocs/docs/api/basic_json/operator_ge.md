# <small>nlohmann::basic_json::</small>operator>=

```cpp
// until C++20
bool operator>=(const_reference lhs, const_reference rhs) noexcept;   // (1)

template<typename ScalarType>
bool operator>=(const_reference lhs, const ScalarType rhs) noexcept(/* see below */); // (2)

template<typename ScalarType>
bool operator>=(ScalarType lhs, const const_reference rhs) noexcept(/* see below */); // (2)
```

1. Compares whether one JSON value `lhs` is greater than or equal to another JSON value `rhs` according to the following
   rules:
    - The comparison always yields `#!cpp false` if (1) either operand is discarded, or (2) either operand is `NaN` and
      the other operand is either `NaN` or any other number.
    - Otherwise, returns the result of `#!cpp !(lhs < rhs)` (see [**operator<**](operator_lt.md)).

2. Compares whether a JSON value is greater than or equal to a scalar or a scalar is greater than or equal to a JSON
   value by converting the scalar to a JSON value and comparing both JSON values according to 1.

## Template parameters

`ScalarType`
:   a scalar type according to `std::is_scalar<ScalarType>::value`

## Parameters

`lhs` (in)
:   first value to consider 

`rhs` (in)
:   second value to consider 

## Return value

whether `lhs` is greater than or equal to `rhs`

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

!!! note "Comparing `NaN`"

    `NaN` values are unordered within the domain of numbers.
    The following comparisons all yield `#!cpp false`:
      1. Comparing a `NaN` with itself.
      2. Comparing a `NaN` with another `NaN`.
      3. Comparing a `NaN` and any other number.

!!! note "Operator overload resolution"

    Since C++20 overload resolution will consider the _rewritten candidate_ generated from
    [`operator<=>`](operator_spaceship.md).

!!! warning "Deprecation"

    If [`JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON`](../macros/json_use_legacy_discarded_value_comparison.md) is
    defined to `1`, the library declares a member `#!cpp bool operator>=(const_reference rhs) const noexcept` in
    C++20 mode to emulate the legacy comparison of discarded values. This member is deprecated since version 3.11.0,
    together with the legacy comparison behavior.

    See the [migration guide](../../integration/migration_guide.md#miscellaneous-functions) for how to update existing
    code.

## Examples

??? example

    The example demonstrates comparing several JSON types.
        
    ```cpp
    --8<-- "examples/operator__greaterequal.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/operator__greaterequal.output"
    ```

## See also

- [**operator<=>**](operator_spaceship.md) comparison: 3-way

## Version history

1. Added in version 1.0.0. Conditionally removed since C++20 in version 3.11.0.
2. Added in version 1.0.0. Conditionally removed since C++20 in version 3.11.0.
   Made conditionally `#!cpp noexcept` in version 3.13.0; before, a throwing conversion called `std::terminate`.
