# basic_json::operator==

```cpp
bool operator==(const_reference lhs, const_reference rhs) noexcept;

template<typename ScalarType>
bool operator==(const_reference lhs, const ScalarType rhs) noexcept;

template<typename ScalarType>
bool operator==(ScalarType lhs, const const_reference rhs) noexcept;
```

Compares two JSON values for equality according to the following rules:

- Two JSON values are equal if (1) they are not discarded, (2) they are from the same type, and (3) their stored values
  are the same according to their respective `operator==`.
- Integer and floating-point numbers are automatically converted before comparison. Note that two NaN values are always
  treated as unequal.

## Template parameters

`ScalarType`
:   a scalar type according to `std::is_scalar<ScalarType>::value`

## Parameters

`lhs` (in)
:   first value to consider 

`rhs` (in)
:   second value to consider 

## Return value

whether the values `lhs` and `rhs` are equal

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Linear.

## Notes

!!! note

    - NaN values never compare equal to themselves or to other NaN values.
    - JSON `#!cpp null` values are all equal.
    - Discarded values never compare equal to themselves.

!!! note

    Floating-point numbers inside JSON values numbers are compared with `json::number_float_t::operator==` which is
    `double::operator==` by default. To compare floating-point while respecting an epsilon, an alternative
    [comparison function](https://github.com/mariokonrad/marnav/blob/master/include/marnav/math/floatingpoint.hpp#L34-#L39)
    could be used, for instance
    
    ```cpp
    template<typename T, typename = typename std::enable_if<std::is_floating_point<T>::value, T>::type>
    inline bool is_same(T a, T b, T epsilon = std::numeric_limits<T>::epsilon()) noexcept
    {
        return std::abs(a - b) <= epsilon;
    }
    ```
    
    Or you can self-defined operator equal function like this:
    
    ```cpp
    bool my_equal(const_reference lhs, const_reference rhs)
    {
        const auto lhs_type lhs.type();
        const auto rhs_type rhs.type();
        if (lhs_type == rhs_type)
        {
            switch(lhs_type)
                // self_defined case
                case value_t::number_float:
                    return std::abs(lhs - rhs) <= std::numeric_limits<float>::epsilon();
                // other cases remain the same with the original
                ...
        }
    ...
    }
    ```

## Example

??? example

    The example demonstrates comparing several JSON types.
        
    ```cpp
    --8<-- "examples/operator__equal.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/operator__equal.output"
    ```

## Version history

- Added in version 1.0.0.
