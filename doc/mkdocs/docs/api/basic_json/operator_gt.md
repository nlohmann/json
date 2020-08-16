# basic_json::operator>

```cpp
bool operator>(const_reference lhs, const_reference rhs) noexcept,

template<typename ScalarType>
bool operator>(const_reference lhs, const ScalarType rhs) noexcept;

template<typename ScalarType>
bool operator>(ScalarType lhs, const const_reference rhs) noexcept;
```

Compares whether one JSON value `lhs` is greater than another JSON value `rhs` by calculating `#!cpp !(lhs <= rhs)`.

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

## Example

??? example

    The example demonstrates comparing several JSON types.
        
    ```cpp
    --8<-- "examples/operator__greater.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/operator__greater.output"
    ```

## Version history

- Added in version 1.0.0.
