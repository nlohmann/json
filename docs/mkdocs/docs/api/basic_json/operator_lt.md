# <small>nlohmann::basic_json::</small>operator<

```cpp
// until C++20
bool operator<(const_reference lhs, const_reference rhs) noexcept;   // (1)

template<typename ScalarType>
bool operator<(const_reference lhs, const ScalarType rhs) noexcept;  // (2)

template<typename ScalarType>
bool operator<(ScalarType lhs, const const_reference rhs) noexcept;  // (2)
```

1. Compares whether one JSON value `lhs` is less than another JSON value `rhs` according to the
  following rules:
    - If either operand is discarded, the comparison yields `#!cpp false`.
    - If both operands have the same type, the values are compared using their respective `operator<`.
    - Integer and floating-point numbers are automatically converted before comparison.
    - In case `lhs` and `rhs` have different types, the values are ignored and the order of the types
      is considered, which is:
        1. null
        2. boolean
        3. number (all types)
        4. object
        5. array
        6. string
        7. binary
      For instance, any boolean value is considered less than any string.

2. Compares whether a JSON value is less than a scalar or a scalar is less than a JSON value by converting
   the scalar to a JSON value and comparing both JSON values according to 1.

## Template parameters

`ScalarType`
:   a scalar type according to `std::is_scalar<ScalarType>::value`

## Parameters

`lhs` (in)
:   first value to consider 

`rhs` (in)
:   second value to consider 

## Return value

whether `lhs` is less than `rhs`

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
    --8<-- "examples/operator__less.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/operator__less.output"
    ```

## See also

- [**operator<=>**](operator_spaceship.md) comparison: 3-way

## Version history

1. Added in version 1.0.0. Conditionally removed since C++20 in version 3.11.0.
2. Added in version 1.0.0. Conditionally removed since C++20 in version 3.11.0.
