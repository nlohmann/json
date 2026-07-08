# <small>nlohmann::basic_json::</small>operator>

```cpp
// until C++20
bool operator>(const_reference lhs, const_reference rhs) noexcept;   // (1)

template<typename ScalarType>
bool operator>(const_reference lhs, const ScalarType rhs) noexcept;  // (2)

template<typename ScalarType>
bool operator>(ScalarType lhs, const const_reference rhs) noexcept;  // (2)
```

1. Compares whether one JSON value `lhs` is greater than another JSON value `rhs` according to the
  following rules:
    - The comparison always yields `#!cpp false` if (1) either operand is discarded, or (2) either
      operand is `NaN` and the other operand is either `NaN` or any other number.
    - Otherwise, returns the result of `#!cpp !(lhs <= rhs)` (see [**operator<=**](operator_le.md)).

2. Compares whether a JSON value is greater than a scalar or a scalar is greater than a JSON value by
   converting the scalar to a JSON value and comparing both JSON values according to 1.

## Template parameters

`ScalarType`
:   a scalar type according to `std::is_scalar<ScalarType>::value`

## Parameters

`lhs` (in)
:   first value to consider 

`rhs` (in)
:   second value to consider 

## Return value

whether `lhs` is greater than `rhs`

## Exception safety

No-throw guarantee: this function never throws exceptions.

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

## Examples

??? example

    The example demonstrates comparing several JSON types.
        
    ```cpp
    --8<-- "examples/operator__greater.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/operator__greater.output"
    ```

## See also

- [**operator<=>**](operator_spaceship.md) comparison: 3-way

## Version history

1. Added in version 1.0.0. Conditionally removed since C++20 in version 3.11.0.
2. Added in version 1.0.0. Conditionally removed since C++20 in version 3.11.0.
