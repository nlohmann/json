# nlohmann::basic_json::operator==

```
// until C++20
bool operator==(const_reference lhs, const_reference rhs) noexcept;   // (1)

template<typename ScalarType>
bool operator==(const_reference lhs, const ScalarType rhs) noexcept;  // (2)

template<typename ScalarType>
bool operator==(ScalarType lhs, const const_reference rhs) noexcept;  // (2)

// since C++20
class basic_json {
    bool operator==(const_reference rhs) const noexcept;              // (1)

    template<typename ScalarType>
    bool operator==(ScalarType rhs) const noexcept;                   // (2)
};
```

1. Compares two JSON values for equality according to the following rules:

   - Two JSON values are equal if (1) neither value is discarded, and (2) they are of the same type and their stored values are the same according to their respective `operator==`.
   - Integer and floating-point numbers are automatically converted before comparison.

1. Compares a JSON value and a scalar or a scalar and a JSON value for equality by converting the scalar to a JSON value and comparing both JSON values according to 1.

## Template parameters

`ScalarType` : a scalar type according to `std::is_scalar<ScalarType>::value`

## Parameters

`lhs` (in) : first value to consider

`rhs` (in) : second value to consider

## Return value

whether the values `lhs`/`*this` and `rhs` are equal

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Linear.

## Notes

Comparing special values

- `NaN` values are unordered within the domain of numbers. The following comparisons all yield `false`:
  1. Comparing a `NaN` with itself.
  1. Comparing a `NaN` with another `NaN`.
  1. Comparing a `NaN` and any other number.
- JSON `null` values are all equal.
- Discarded values never compare equal to themselves.

Comparing floating-point numbers

Floating-point numbers inside JSON values numbers are compared with `json::number_float_t::operator==` which is `double::operator==` by default. To compare floating-point while respecting an epsilon, an alternative [comparison function](https://github.com/mariokonrad/marnav/blob/master/include/marnav/math/floatingpoint.hpp#L34-#L39) could be used, for instance

```
template<typename T, typename = typename std::enable_if<std::is_floating_point<T>::value, T>::type>
inline bool is_same(T a, T b, T epsilon = std::numeric_limits<T>::epsilon()) noexcept
{
    return std::abs(a - b) <= epsilon;
}
```

Or you can define your own equality function like this:

```
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

Comparing different `basic_json` specializations

Comparing different `basic_json` specializations can have surprising effects. For instance, the result of comparing the JSON objects

```
{
   "version": 1,
   "type": "integer"
}
```

and

```
{
   "type": "integer",
   "version": 1
}
```

depends on whether [`nlohmann::json`](https://json.nlohmann.me/api/json/index.md) or [`nlohmann::ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md) is used:

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    nlohmann::json uj1 = {{"version", 1}, {"type", "integer"}};
    nlohmann::json uj2 = {{"type", "integer"}, {"version", 1}};

    nlohmann::ordered_json oj1 = {{"version", 1}, {"type", "integer"}};
    nlohmann::ordered_json oj2 = {{"type", "integer"}, {"version", 1}};

    std::cout << std::boolalpha << (uj1 == uj2) << '\n' << (oj1 == oj2) << std::endl;
}
```

Output:

```
true
false
```

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
    std::cout << array_1 << " == " << array_2 << " " << (array_1 == array_2) << '\n';
    std::cout << object_1 << " == " << object_2 << " " << (object_1 == object_2) << '\n';
    std::cout << number_1 << " == " << number_2 << " " << (number_1 == number_2) << '\n';
    std::cout << string_1 << " == " << string_2 << " " << (string_1 == string_2) << '\n';
}
```

Output:

```
[1,2,3] == [1,2,4] false
{"A":"a","B":"b"} == {"A":"a","B":"b"} true
17 == 17.0 true
"foo" == "bar" false
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
    std::cout << array << " == nullptr " << (array == nullptr) << '\n';
    std::cout << object << " == nullptr " << (object == nullptr) << '\n';
    std::cout << number << " == nullptr " << (number == nullptr) << '\n';
    std::cout << string << " == nullptr " << (string == nullptr) << '\n';
    std::cout << null << " == nullptr " << (null == nullptr) << '\n';
}
```

Output:

```
[1,2,3] == nullptr false
{"A":"a","B":"b"} == nullptr false
17 == nullptr false
"foo" == nullptr false
null == nullptr true
```

## See also

- [operator!=](https://json.nlohmann.me/api/basic_json/operator_ne/index.md) compare for inequality
- [operator\<=>](https://json.nlohmann.me/api/basic_json/operator_spaceship/index.md) comparison: 3-way (C++20)

## Version history

1. Added in version 1.0.0. Added C++20 member functions in version 3.11.0.
1. Added in version 1.0.0. Added C++20 member functions in version 3.11.0.
