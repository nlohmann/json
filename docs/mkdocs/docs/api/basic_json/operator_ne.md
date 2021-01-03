# <small>nlohmann::basic_json::</small>operator!=

```cpp
// until C++20
bool operator!=(const_reference lhs, const_reference rhs) noexcept;   // (1)

template<typename ScalarType>
bool operator!=(const_reference lhs, const ScalarType rhs) noexcept;  // (2)

template<typename ScalarType>
bool operator!=(ScalarType lhs, const const_reference rhs) noexcept;  // (2)

// since C++20
class basic_json {
    bool operator!=(const_reference rhs) const noexcept;              // (1)

    template<typename ScalarType>
    bool operator!=(ScalarType rhs) const noexcept;                   // (2)
};
```

1. Compares two JSON values for inequality according to the following rules:
    - The comparison always yields `#!cpp false` if (1) either operand is discarded, or (2) either operand is `NaN` and
      the other operand is either `NaN` or any other number.
    - Otherwise, returns the result of `#!cpp !(lhs == rhs)` (until C++20) or `#!cpp !(*this == rhs)` (since C++20).

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

## Examples

??? example

    The example demonstrates comparing several JSON types.
        
    ```cpp
    --8<-- "examples/operator__notequal.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/operator__notequal.output"
    ```

??? example

    The example demonstrates comparing several JSON types against the null pointer (JSON `#!json null`).
        
    ```cpp
    --8<-- "examples/operator__notequal__nullptr_t.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/operator__notequal__nullptr_t.output"
    ```

## Version history

1. Added in version 1.0.0. Added C++20 member functions in version 3.11.0.
2. Added in version 1.0.0. Added C++20 member functions in version 3.11.0.
