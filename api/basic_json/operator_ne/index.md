# nlohmann::basic_json::operator!=

```
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

1. Compares two JSON values for inequality. Returns `!(lhs == rhs)` (until C++20) or `!(*this == rhs)` (since C++20).

   - This means the comparison is simply the logical negation of `operator==`, including for special values like `NaN` and `discarded`.

1. Compares a JSON value and a scalar or a scalar and a JSON value for inequality by converting the scalar to a JSON value and comparing both JSON values according to 1.

## Template parameters

`ScalarType` : a scalar type according to `std::is_scalar<ScalarType>::value`

## Parameters

`lhs` (in) : first value to consider

`rhs` (in) : second value to consider

## Return value

whether the values `lhs`/`*this` and `rhs` are not equal

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Linear.

## Notes

Comparing `NaN` and `discarded`

Since `operator!=` is defined as `!(a == b)`, the behavior for special values follows that of `operator==`:

- For `NaN` values: `NaN == NaN` yields `false`, so `NaN != NaN` yields `true`.
- For `discarded` values: `discarded == x` yields `false` for any `x`, so `discarded != x` yields `true`.

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
    json number_2 = 17.000000000000001L;
    json string_1 = "foo";
    json string_2 = "bar";

    // output values and comparisons
    std::cout << std::boolalpha;
    std::cout << array_1 << " != " << array_2 << " " << (array_1 != array_2) << '\n';
    std::cout << object_1 << " != " << object_2 << " " << (object_1 != object_2) << '\n';
    std::cout << number_1 << " != " << number_2 << " " << (number_1 != number_2) << '\n';
    std::cout << string_1 << " != " << string_2 << " " << (string_1 != string_2) << '\n';
}
```

Output:

```
[1,2,3] != [1,2,4] true
{"A":"a","B":"b"} != {"A":"a","B":"b"} false
17 != 17.0 false
"foo" != "bar" true
```

Example

The example demonstrates comparing several JSON types against the null pointer (JSON `null`).

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create several JSON values
    json array = {1, 2, 3};
    json object = {{"A", "a"}, {"B", "b"}};
    json number = 17;
    json string = "foo";
    json null;

    // output values and comparisons
    std::cout << std::boolalpha;
    std::cout << array << " != nullptr " << (array != nullptr) << '\n';
    std::cout << object << " != nullptr " << (object != nullptr) << '\n';
    std::cout << number << " != nullptr " << (number != nullptr) << '\n';
    std::cout << string << " != nullptr " << (string != nullptr) << '\n';
    std::cout << null << " != nullptr " << (null != nullptr) << '\n';
}
```

Output:

```
[1,2,3] != nullptr true
{"A":"a","B":"b"} != nullptr true
17 != nullptr true
"foo" != nullptr true
null != nullptr false
```

## Version history

1. Added in version 1.0.0. Added C++20 member functions in version 3.11.0. Changed in version 3.13.0 to remove special-casing for `NaN` and `discarded` values; `operator!=` now consistently means `!(a == b)`.
1. Added in version 1.0.0. Added C++20 member functions in version 3.11.0. Changed in version 3.13.0 to remove special-casing for `NaN` and `discarded` values; `operator!=` now consistently means `!(a == b)`.
