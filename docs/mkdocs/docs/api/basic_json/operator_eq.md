# <small>nlohmann::basic_json::</small>operator==

```cpp
// until C++20
bool operator==(const_reference lhs, const_reference rhs) noexcept;   // (1)

template<typename ScalarType>
bool operator==(const_reference lhs, const ScalarType rhs) noexcept(/* see below */); // (2)

template<typename ScalarType>
bool operator==(ScalarType lhs, const const_reference rhs) noexcept(/* see below */); // (2)

// since C++20
class basic_json {
    bool operator==(const_reference rhs) const noexcept;              // (1)

    template<typename ScalarType>
    bool operator==(ScalarType rhs) const noexcept(/* see below */); // (2)
};
```

1. Compares two JSON values for equality according to the following rules:
    - Two JSON values are equal if (1) neither value is discarded, and (2) they are of the same type and their stored
      values are the same according to their respective `operator==`.
    - Integer and floating-point numbers are automatically converted before comparison.

2. Compares a JSON value and a scalar or a scalar and a JSON value for equality by converting the
   scalar to a JSON value and comparing both JSON values according to 1.

## Template parameters

`ScalarType`
:   a scalar type according to `std::is_scalar<ScalarType>::value`

## Parameters

`lhs` (in)
:   first value to consider 

`rhs` (in)
:   second value to consider 

## Return value

whether the values `lhs`/`*this` and `rhs` are equal

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

!!! note "Comparing special values"

    - `NaN` values are unordered within the domain of numbers.
      The following comparisons all yield `#!cpp false`:
        1. Comparing a `NaN` with itself.
        2. Comparing a `NaN` with another `NaN`.
        3. Comparing a `NaN` and any other number.
    - JSON `#!cpp null` values are all equal.
    - Discarded values never compare equal to themselves.

!!! note "Comparing floating-point numbers"

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
    
    Or you can define your own equality function like this:
    
    ```cpp
    bool my_equal(const_reference lhs, const_reference rhs)
    {
        const auto lhs_type = lhs.type();
        const auto rhs_type = rhs.type();
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

!!! note "Comparing different `basic_json` specializations"

    Comparing different `basic_json` specializations can have surprising effects. For instance, the result of comparing
    the JSON objects

    ```json
    {
       "version": 1,
       "type": "integer"
    }
    ```

    and

    ```json
    {
       "type": "integer",
       "version": 1
    }
    ```

    depends on whether [`nlohmann::json`](../json.md) or [`nlohmann::ordered_json`](../ordered_json.md) is used:

     ```cpp
     --8<-- "examples/operator__equal__specializations.cpp"
     ```
     
     Output:
     
     ```json
     --8<-- "examples/operator__equal__specializations.output"
     ```

## Examples

??? example "Example: (1) compare JSON values"

    The example demonstrates comparing several JSON types.
        
    ```cpp
    --8<-- "examples/operator__equal.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/operator__equal.output"
    ```

??? example "Example: (2) compare JSON values with `#!cpp nullptr`"

    The example demonstrates comparing several JSON types against the null pointer (JSON `#!json null`).
        
    ```cpp
    --8<-- "examples/operator__equal__nullptr_t.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/operator__equal__nullptr_t.output"
    ```

## See also

- [operator!=](operator_ne.md) compare for inequality
- [operator<=>](operator_spaceship.md) comparison: 3-way (C++20)
- [basic_json_view::operator==](../basic_json_view/operator_eq.md) - the same comparison on a zero-copy view, without
  building a `basic_json` value for it

## Version history

1. Added in version 1.0.0. Added C++20 member functions in version 3.11.0.
2. Added in version 1.0.0. Added C++20 member functions in version 3.11.0.
   Made conditionally `#!cpp noexcept` in version 3.13.0; before, a throwing conversion called `std::terminate`.
