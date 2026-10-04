# <small>nlohmann::basic_json::</small>operator<=>

```cpp
// since C++20
class basic_json {
    std::partial_ordering operator<=>(const_reference rhs) const noexcept;  // (1)

    template<typename ScalarType>
    std::partial_ordering operator<=>(const ScalarType rhs) const noexcept(/* see below */); // (2)
};
```

1. 3-way compares two JSON values producing a result of type `std::partial_ordering` according to the following rules:
    - Two JSON values compare with a result of `std::partial_ordering::unordered` if either value is discarded.
    - If both JSON values are of the same type, the result is produced by 3-way comparing their stored values using
      their respective `operator<=>`.
    - Integer and floating-point numbers are converted to their common type and then 3-way compared using their
      respective `operator<=>`.
      For instance, comparing an integer and a floating-point value will 3-way compare the first value converted to
      floating-point with the second value.
    - Otherwise, yields a result by comparing the type (see [`value_t`](value_t.md)).
  
2. 3-way compares a JSON value and a scalar or a scalar and a JSON value by converting the scalar to a JSON value and
   3-way comparing both JSON values (see 1).

## Template parameters

`ScalarType`
:   a scalar type according to `std::is_scalar<ScalarType>::value`

## Parameters

`rhs` (in)
:   second value to consider 

## Return value

the `std::partial_ordering` of the 3-way comparison of `*this` and `rhs`

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

    - `NaN` values are unordered within the domain of numbers.
      The following comparisons all yield `std::partial_ordering::unordered`:
        1. Comparing a `NaN` with itself.
        2. Comparing a `NaN` with another `NaN`.
        3. Comparing a `NaN` and any other number.

## Examples

??? example "Example: (1) comparing JSON values"

    The example demonstrates comparing several JSON values.
    
    ```cpp
    --8<-- "examples/operator_spaceship__const_reference.c++20.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/operator_spaceship__const_reference.c++20.output"
    ```

??? example "Example: (2) comparing JSON values and scalars"

    The example demonstrates comparing several JSON values and scalars.
    
    ```cpp
    --8<-- "examples/operator_spaceship__scalartype.c++20.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/operator_spaceship__scalartype.c++20.output"
    ```

## See also

- [**operator==**](operator_eq.md) - comparison: equal
- [**operator!=**](operator_ne.md) - comparison: not equal
- [**operator<**](operator_lt.md) - comparison: less than
- [**operator<=**](operator_le.md) - comparison: less than or equal
- [**operator>**](operator_gt.md) - comparison: greater than
- [**operator>=**](operator_ge.md) - comparison: greater than or equal

## Version history

1. Added in version 3.11.0.
2. Added in version 3.11.0.
   Made conditionally `#!cpp noexcept` in version 3.13.0; before, a throwing conversion called `std::terminate`.
