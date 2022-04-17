# <small>nlohmann::basic_json::</small>operator<=>

```cpp
// since C++20
class basic_json {
    std::partial_ordering operator<=>(const_reference rhs) const noexcept;  // (1)

    template<typename ScalarType>
    std::partial_ordering operator<=>(const ScalarType rhs) const noexcept; // (2)
};
```

1. 3-way compares two JSON values producing a result of type `std::partial_ordering` according to the following rules:
    - Two JSON values compare with a result of `std::partial_ordering::unordered` if either value is discarded.
    - If both JSON values are of the same type, the result is produced by 3-way comparing their stored values using their
      respective `operator<=>`.
    - Integer and floating-point numbers are converted to their common type and then 3-way compared using their respective
      `operator<=>`.
      For instance, comparing an integer and a floating-point value will 3-way compare the first value convertered to
      floating-point with the second value.
    - Otherwise, yields a result by comparing the type (see [`value_t`](value_t.md)).
  
2. 3-way compares a JSON value and a scalar or a scalar and a JSON value by converting the scalar to a JSON value and 3-way
   comparing both JSON values (see 1).

## Template parameters

`ScalarType`
:   a scalar type according to `std::is_scalar<ScalarType>::value`

## Parameters

`rhs` (in)
:   second value to consider 

## Return value

the `std::partial_ordering` of the 3-way comparison of `*this` and `rhs`

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Linear.

## Notes

!!! note "Comparing `NaN`"

    - `NaN` values are unordered within the domain of numbers.
      The following comparisons all yield `std::partial_ordering::unordered`:
        1. Comparing a `NaN` with itself.
        2. Comparing a `NaN` with another `NaN`.
        3. Comparing a `NaN` and any other number.

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
