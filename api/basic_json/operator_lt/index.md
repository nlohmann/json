# nlohmann::basic_json::operator\<

```
// until C++20
bool operator<(const_reference lhs, const_reference rhs) noexcept;   // (1)

template<typename ScalarType>
bool operator<(const_reference lhs, const ScalarType rhs) noexcept;  // (2)

template<typename ScalarType>
bool operator<(ScalarType lhs, const const_reference rhs) noexcept;  // (2)
```

1. Compares whether one JSON value `lhs` is less than another JSON value `rhs` according to the following rules:

   - If either operand is discarded, the comparison yields `false`.
   - If both operands have the same type, the values are compared using their respective `operator<`.
   - Integer and floating-point numbers are automatically converted before comparison.
   - In case `lhs` and `rhs` have different types, the values are ignored and the order of the types is considered, which is:
     1. null
     1. boolean
     1. number (all types)
     1. object
     1. array
     1. string
     1. binary For instance, any boolean value is considered less than any string.

1. Compares whether a JSON value is less than a scalar or a scalar is less than a JSON value by converting the scalar to a JSON value and comparing both JSON values according to 1.

## Template parameters

`ScalarType` : a scalar type according to `std::is_scalar<ScalarType>::value`

## Parameters

`lhs` (in) : first value to consider

`rhs` (in) : second value to consider

## Return value

whether `lhs` is less than `rhs`

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Linear.

## Notes

Comparing `NaN`

`NaN` values are unordered within the domain of numbers. The following comparisons all yield `false`:

1. Comparing a `NaN` with itself.
1. Comparing a `NaN` with another `NaN`.
1. Comparing a `NaN` and any other number.

Operator overload resolution

Since C++20 overload resolution will consider the *rewritten candidate* generated from [`operator<=>`](https://json.nlohmann.me/api/basic_json/operator_spaceship/index.md).

## Examples

Example

The example demonstrates comparing several JSON types.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create several JSON values
    json array_1 = {1, 2, 3};
    json array_2 = {1, 2, 4};
    json object_1 = {{"A", "a"}, {"B", "b"}};
    json object_2 = {{"B", "b"}, {"A", "a"}};
    json number_1 = 17;
    json number_2 = 17.0000000000001L;
    json string_1 = "foo";
    json string_2 = "bar";

    // output values and comparisons
    std::cout << std::boolalpha;
    std::cout << array_1 << " == " << array_2 << " " << (array_1 < array_2) << '\n';
    std::cout << object_1 << " == " << object_2 << " " << (object_1 < object_2) << '\n';
    std::cout << number_1 << " == " << number_2 << " " << (number_1 < number_2) << '\n';
    std::cout << string_1 << " == " << string_2 << " " << (string_1 < string_2) << '\n';
}
```

Output:

```
[1,2,3] == [1,2,4] true
{"A":"a","B":"b"} == {"A":"a","B":"b"} false
17 == 17.0000000000001 true
"foo" == "bar" false
```

## See also

- [**operator\<=>**](https://json.nlohmann.me/api/basic_json/operator_spaceship/index.md) comparison: 3-way

## Version history

1. Added in version 1.0.0. Conditionally removed since C++20 in version 3.11.0.
1. Added in version 1.0.0. Conditionally removed since C++20 in version 3.11.0.
