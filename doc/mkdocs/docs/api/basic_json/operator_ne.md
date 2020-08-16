# basic_json::operator!=

```cpp
bool operator!=(const_reference lhs, const_reference rhs) noexcept;

template<typename ScalarType>
bool operator!=(const_reference lhs, const ScalarType rhs) noexcept;

template<typename ScalarType>
bool operator!=(ScalarType lhs, const const_reference rhs) noexcept;
```

Compares two JSON values for inequality by calculating `#!cpp !(lhs == rhs)`.

## Template parameters

`ScalarType`
:   a scalar type according to `std::is_scalar<ScalarType>::value`

## Parameters

`lhs` (in)
:   first value to consider 

`rhs` (in)
:   second value to consider 

## Return value

whether the values `lhs` and `rhs` are not equal

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Linear.

## Example

The example demonstrates comparing several JSON
types.
    
```cpp
--8<-- "examples/operator__notequal.cpp"
```

Output:

```json
--8<-- "examples/operator__notequal.output"
```

## Version history

- Added in version 1.0.0.
