# <small>nlohmann::basic_json::</small>operator<

```cpp
bool operator<(const_reference lhs, const_reference rhs) noexcept;

template<typename ScalarType>
bool operator<(const_reference lhs, const ScalarType rhs) noexcept;

template<typename ScalarType>
bool operator<(ScalarType lhs, const const_reference rhs) noexcept;
```

Compares whether one JSON value `lhs` is less than another JSON value `rhs` according to the following rules:

- If `lhs` and `rhs` have the same type, the values are compared using the default `<` operator.
- Integer and floating-point numbers are automatically converted before comparison
- Discarded values a
- In case `lhs` and `rhs` have different types, the values are ignored and the order of the types is considered, which
  is:
    1. null
    2. boolean
    3. number (all types)
    4. object
    5. array
    6. string
    7. binary

    For instance, any boolean value is considered less than any string.

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

## Version history

- Added in version 1.0.0.
